/**
 * @author Rob Vella, KK9ROB <me@robvella.com>
 * @copyright Copyright (c) 2020 AllStarLink, Inc
 * @license AGPL-3.0-or-later
 */
const axios = require('axios');
const Agent = require('agentkeepalive');

const keepaliveAgent = new Agent({
  maxSockets: 100,
  maxFreeSockets: 10,
  timeout: 60000, // active socket keepalive for 60 seconds
  freeSocketTimeout: 30000, // free socket keepalive for 30 seconds
});

axios.defaults.headers.common['Accept'] = 'application/json';
axios.defaults.headers.common['Authorization'] = 'Bearer ' + process.env.API_TOKEN;
axios.defaults.headers.common['User-Agent'] = 'ASL-IAXBridge/0.0.1';
axios.defaults.httpAgent = keepaliveAgent;
axios.defaults.httpsAgent = keepaliveAgent

// const axiosInstance = axios.create();

const Axios = () => {
  const apiPrefix = process.env.API_URL;

  const apiUrl = (postFix) => {
    return apiPrefix + postFix
  };

  return {
    request: (config) => axiosInstance.request(config),
    get: (url, config) => axiosInstance.get(apiUrl(url), config),
    delete: (url, config) => axiosInstance.delete(apiUrl(url), config),
    head: (url, config) => axiosInstance.head(apiUrl(url), config),
    post: (url, data, config) => axiosInstance.post(apiUrl(url), data, config),
    put: (url, data, config) => axiosInstance.put(apiUrl(url), data, config),
    patch: (url, data, config) => axiosInstance.patch(apiUrl(url), data, config),
    axios: axiosInstance
  }
};

module.exports = Axios;