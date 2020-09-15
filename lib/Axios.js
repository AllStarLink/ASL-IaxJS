/**
 * @author Rob Vella, KK9ROB <me@robvella.com>
 * @copyright Copyright (c) 2020 AllStarLink, Inc
 * @license GPL-3.0-only
 */
const axios = require('axios');

axios.defaults.headers.common['Accept'] = 'application/json';
axios.defaults.headers.common['Authorization'] = 'Bearer ' + process.env.API_TOKEN;

const Axios = () => {
    const apiPrefix = process.env.API_URL;

    const apiUrl = (postFix) => {
        return apiPrefix + postFix
    };

    return {
        request: (config) => axios.request(config),
        get: (url, config) => axios.get(apiUrl(url), config),
        delete: (url, config) => axios.delete(apiUrl(url), config),
        head: (url, config) => axios.head(apiUrl(url), config),
        post: (url, data, config) => axios.post(apiUrl(url), data, config),
        put: (url, data, config) => axios.put(apiUrl(url), data, config),
        patch: (url, data, config) => axios.patch(apiUrl(url), data, config),
        axios: axios
    }
};

module.exports = Axios;