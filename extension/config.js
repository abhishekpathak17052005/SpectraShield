/**
 * SpectraShield Extension Configuration
 * Provides dynamic endpoint resolution for Cloud (Production) and Local (Development).
 */
var SPECTRA_CONFIG = {
  CLOUD_API_BASE: 'https://spectrashield-3h3d.onrender.com',
  CLOUD_SOC_URL: 'https://spectrashield-tau.vercel.app',
  LOCAL_API_BASE: 'http://localhost:8000',
  LOCAL_SOC_URL: 'http://localhost:5173',
  DEFAULT_ENV: 'cloud'
};

function getSpectraEndpoints(callback) {
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    chrome.storage.local.get(['spectra_env', 'spectra_api_base', 'spectra_soc_url'], function (res) {
      var env = (res && res.spectra_env) || SPECTRA_CONFIG.DEFAULT_ENV;
      var apiBase = res && res.spectra_api_base;
      var socUrl = res && res.spectra_soc_url;

      // Migrate from generic placeholder if previously saved
      if (socUrl === 'https://spectrashield.vercel.app' || !socUrl) {
        socUrl = (env === 'local') ? SPECTRA_CONFIG.LOCAL_SOC_URL : SPECTRA_CONFIG.CLOUD_SOC_URL;
      }
      if (!apiBase) {
        apiBase = (env === 'local') ? SPECTRA_CONFIG.LOCAL_API_BASE : SPECTRA_CONFIG.CLOUD_API_BASE;
      }

      callback({
        env: env,
        apiBase: apiBase.replace(/\/$/, ''),
        socUrl: socUrl.replace(/\/$/, '')
      });
    });
  } else {
    callback({
      env: SPECTRA_CONFIG.DEFAULT_ENV,
      apiBase: SPECTRA_CONFIG.CLOUD_API_BASE,
      socUrl: SPECTRA_CONFIG.CLOUD_SOC_URL
    });
  }
}
