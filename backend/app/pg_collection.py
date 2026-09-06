from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any

from psycopg2.extras import Json


@dataclass
class DeleteResult:
    deleted_count: int


@dataclass
class UpdateResult:
    matched_count: int
    modified_count: int
    upserted_id: str | None = None


def _json_ready(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: _json_ready(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_ready(v) for v in value]
    return value


def _get_nested(source: dict[str, Any], dotted_key: str) -> Any:
    current: Any = source
    for part in dotted_key.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _set_nested(target: dict[str, Any], dotted_key: str, value: Any) -> None:
    parts = dotted_key.split(".")
    current = target
    for part in parts[:-1]:
        if part not in current or not isinstance(current[part], dict):
            current[part] = {}
        current = current[part]
    current[parts[-1]] = value


class PostgresCollection:
    """
    High-performance PostgreSQL / Supabase JSONB collection driver.
    """

    def __init__(
        self,
        *,
        connection,
        table_name: str,
        key_column: str,
        key_field: str,
        extra_columns: list[str] | None = None,
    ):
        self.connection = connection
        self.table_name = table_name
        self.key_column = key_column
        self.key_field = key_field
        self.extra_columns = extra_columns or []

    def _row_to_doc(self, row: dict[str, Any]) -> dict[str, Any]:
        payload = dict(row.get("payload") or {})

        key_val = row.get(self.key_column)
        if key_val is not None:
            payload[self.key_field] = key_val

        for col in self.extra_columns:
            col_val = row.get(col)
            if col_val is not None and col not in payload:
                payload[col] = col_val

        return payload

    def _matches_filter(self, doc: dict[str, Any], flt: dict[str, Any]) -> bool:
        for key, expected in (flt or {}).items():
            current = _get_nested(doc, key)

            if isinstance(expected, dict):
                in_values = expected.get("$in")
                if in_values is not None:
                    if current not in in_values:
                        return False
                    continue
                return False

            if current != expected:
                return False

        return True

    def _apply_projection(self, doc: dict[str, Any], projection: dict[str, int] | None) -> dict[str, Any]:
        if not projection or projection == {"_id": 0}:
            return dict(doc)

        include_fields = [k for k, v in projection.items() if k != "_id" and int(v) == 1]
        if not include_fields:
            return dict(doc)

        projected: dict[str, Any] = {}
        for field in include_fields:
            value = _get_nested(doc, field)
            if value is not None:
                _set_nested(projected, field, value)
        return projected

    def _select_rows(self, flt: dict[str, Any] | None) -> list[dict[str, Any]]:
        where_parts: list[str] = []
        params: list[Any] = []

        for key, value in (flt or {}).items():
            if isinstance(value, dict):
                continue

            if key == self.key_field:
                where_parts.append(f"{self.key_column} = %s")
                params.append(value)
            elif key in self.extra_columns:
                where_parts.append(f"{key} = %s")
                params.append(value)
            else:
                where_parts.append("payload ->> %s = %s")
                params.extend([key, str(value)])

        sql = f"SELECT {self.key_column}, payload"
        if self.extra_columns:
            sql += ", " + ", ".join(self.extra_columns)
        sql += f" FROM {self.table_name}"
        if where_parts:
            sql += " WHERE " + " AND ".join(where_parts)

        with self.connection.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()

        return rows

    def _insert_payload(self, doc: dict[str, Any]) -> str:
        key_val = doc.get(self.key_field)
        if key_val is None:
            if self.key_field == "id":
                key_val = str(uuid.uuid4())[:8]
            else:
                raise ValueError(f"Missing required key field: {self.key_field}")

        clean_doc = dict(doc)
        clean_doc[self.key_field] = key_val

        payload = _json_ready(clean_doc)
        col_names = [self.key_column, "payload"]
        values = [key_val, Json(payload)]
        placeholders = ["%s", "%s"]

        for col in self.extra_columns:
            col_val = clean_doc.get(col)
            col_names.append(col)
            values.append(col_val)
            placeholders.append("%s")

        sql = (
            f"INSERT INTO {self.table_name} ({', '.join(col_names)}) "
            f"VALUES ({', '.join(placeholders)})"
        )

        with self.connection.cursor() as cur:
            cur.execute(sql, values)

        return str(key_val)

    def find_one(self, flt: dict[str, Any], projection: dict[str, int] | None = None) -> dict[str, Any] | None:
        rows = self._select_rows(flt)
        for row in rows:
            doc = self._row_to_doc(row)
            if self._matches_filter(doc, flt):
                return self._apply_projection(doc, projection)
        return None

    def find(self, flt: dict[str, Any] | None = None, projection: dict[str, int] | None = None) -> list[dict[str, Any]]:
        rows = self._select_rows(flt)
        docs: list[dict[str, Any]] = []
        for row in rows:
            doc = self._row_to_doc(row)
            if self._matches_filter(doc, flt or {}):
                docs.append(self._apply_projection(doc, projection))
        return docs

    def insert_one(self, doc: dict[str, Any]) -> dict[str, str]:
        inserted_id = self._insert_payload(doc)
        return {"inserted_id": inserted_id}

    def count_documents(self, flt: dict[str, Any] | None) -> int:
        return len(self.find(flt or {}))

    def delete_many(self, flt: dict[str, Any] | None) -> DeleteResult:
        if not flt:
            with self.connection.cursor() as cur:
                cur.execute(f"DELETE FROM {self.table_name}")
                deleted = cur.rowcount
            return DeleteResult(deleted_count=int(deleted or 0))

        rows = self._select_rows(flt)
        keys_to_delete: list[Any] = []
        for row in rows:
            doc = self._row_to_doc(row)
            if self._matches_filter(doc, flt):
                keys_to_delete.append(row.get(self.key_column))

        if not keys_to_delete:
            return DeleteResult(deleted_count=0)

        with self.connection.cursor() as cur:
            cur.execute(
                f"DELETE FROM {self.table_name} WHERE {self.key_column} = ANY(%s)",
                (keys_to_delete,),
            )
            deleted = cur.rowcount

        return DeleteResult(deleted_count=int(deleted or 0))

    def delete_one(self, flt: dict[str, Any]) -> DeleteResult:
        result = self.delete_many(flt)
        deleted = 1 if result.deleted_count > 0 else 0
        return DeleteResult(deleted_count=deleted)

    def update_one(self, flt: dict[str, Any], update: dict[str, Any], upsert: bool = False) -> UpdateResult:
        set_map = dict(update.get("$set") or {})
        set_on_insert = dict(update.get("$setOnInsert") or {})

        existing = self.find_one(flt)
        if existing is not None:
            merged = dict(existing)
            merged.update(set_map)

            key_val = merged.get(self.key_field)
            if key_val is None:
                return UpdateResult(matched_count=0, modified_count=0)

            payload = _json_ready(merged)
            values: list[Any] = [Json(payload)]

            set_sql_parts = ["payload = %s"]
            for col in self.extra_columns:
                if col in merged:
                    set_sql_parts.append(f"{col} = %s")
                    values.append(merged.get(col))

            values.append(key_val)
            with self.connection.cursor() as cur:
                cur.execute(
                    f"UPDATE {self.table_name} SET {', '.join(set_sql_parts)} WHERE {self.key_column} = %s",
                    values,
                )
            return UpdateResult(matched_count=1, modified_count=1)

        if not upsert:
            return UpdateResult(matched_count=0, modified_count=0)

        merged = dict(set_on_insert)
        merged.update(set_map)
        for key, value in flt.items():
            if isinstance(value, dict):
                continue
            merged.setdefault(key, value)

        inserted_id = self._insert_payload(merged)
        return UpdateResult(matched_count=0, modified_count=0, upserted_id=inserted_id)


class InMemoryCollection:
    """
    In-memory collection with method parity to PostgresCollection.
    Provides reliable, zero-config local storage for automated tests and offline dev.
    """

    def __init__(self, name: str, key_field: str = "id"):
        self.name = name
        self.key_field = key_field
        self._docs: list[dict[str, Any]] = []

    def _matches_filter(self, doc: dict[str, Any], flt: dict[str, Any]) -> bool:
        for key, expected in (flt or {}).items():
            current = _get_nested(doc, key)

            if isinstance(expected, dict):
                in_values = expected.get("$in")
                if in_values is not None:
                    if current not in in_values:
                        return False
                    continue
                return False

            if current != expected:
                return False

        return True

    def _apply_projection(self, doc: dict[str, Any], projection: dict[str, int] | None) -> dict[str, Any]:
        if not projection or projection == {"_id": 0}:
            return dict(doc)

        include_fields = [k for k, v in projection.items() if k != "_id" and int(v) == 1]
        if not include_fields:
            return dict(doc)

        projected: dict[str, Any] = {}
        for field in include_fields:
            value = _get_nested(doc, field)
            if value is not None:
                _set_nested(projected, field, value)
        return projected

    def find_one(self, flt: dict[str, Any], projection: dict[str, int] | None = None) -> dict[str, Any] | None:
        for doc in self._docs:
            if self._matches_filter(doc, flt):
                return self._apply_projection(doc, projection)
        return None

    def find(self, flt: dict[str, Any] | None = None, projection: dict[str, int] | None = None) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for doc in self._docs:
            if self._matches_filter(doc, flt or {}):
                results.append(self._apply_projection(doc, projection))
        return results

    def insert_one(self, doc: dict[str, Any]) -> dict[str, str]:
        clean_doc = dict(doc)
        if self.key_field not in clean_doc or clean_doc[self.key_field] is None:
            clean_doc[self.key_field] = str(uuid.uuid4())[:8]
        key_val = str(clean_doc[self.key_field])
        self._docs.append(clean_doc)
        return {"inserted_id": key_val}

    def count_documents(self, flt: dict[str, Any] | None = None) -> int:
        return len(self.find(flt or {}))

    def delete_many(self, flt: dict[str, Any] | None = None) -> DeleteResult:
        if not flt:
            count = len(self._docs)
            self._docs.clear()
            return DeleteResult(deleted_count=count)

        remaining = []
        deleted = 0
        for doc in self._docs:
            if self._matches_filter(doc, flt):
                deleted += 1
            else:
                remaining.append(doc)
        self._docs = remaining
        return DeleteResult(deleted_count=deleted)

    def delete_one(self, flt: dict[str, Any]) -> DeleteResult:
        for i, doc in enumerate(self._docs):
            if self._matches_filter(doc, flt):
                self._docs.pop(i)
                return DeleteResult(deleted_count=1)
        return DeleteResult(deleted_count=0)

    def update_one(self, flt: dict[str, Any], update: dict[str, Any], upsert: bool = False) -> UpdateResult:
        set_map = dict(update.get("$set") or {})
        set_on_insert = dict(update.get("$setOnInsert") or {})

        for i, doc in enumerate(self._docs):
            if self._matches_filter(doc, flt):
                self._docs[i].update(set_map)
                return UpdateResult(matched_count=1, modified_count=1)

        if not upsert:
            return UpdateResult(matched_count=0, modified_count=0)

        merged = dict(set_on_insert)
        merged.update(set_map)
        for key, value in flt.items():
            if isinstance(value, dict):
                continue
            merged.setdefault(key, value)

        if self.key_field not in merged or merged[self.key_field] is None:
            merged[self.key_field] = str(uuid.uuid4())[:8]
        self._docs.append(merged)
        return UpdateResult(matched_count=0, modified_count=0, upserted_id=str(merged[self.key_field]))

    def create_index(self, *args, **kwargs) -> None:
        """Compatibility no-op."""
        pass

