/**
 * @author Rob Vella, KK9ROB <me@robvella.com>
 * @author Jason VE3YCA
 * @copyright Copyright (c) 2020 AllStarLink, Inc
 * @license AGPL-3.0-or-later
 */
const Axios = require('./Axios')();
const RegisterApi = {
  /**
   *
   * @param node
   * @param challenge
   * @param challengeResponse
   * @param ip
   * @param port
   * @returns {Promise<*|boolean|undefined>}
   */
  async register(node, challenge, challengeResponse, ip, port) {
    return this.doRegUnreg(0, node, challenge, challengeResponse, ip, port)
  },
  /**
   *
   * @param node
   * @param challenge
   * @param challengeResponse
   * @param ip
   * @param port
   * @returns {Promise<*|boolean|undefined>}
   */
  async unregister(node, challenge, challengeResponse, ip, port) {
    return this.doRegUnreg(1, node, challenge, challengeResponse, ip, port)
  },
  /**
   *
   * @param type
   * @param node
   * @param challenge
   * @param challengeResponse
   * @param ip
   * @param port
   * @returns {Promise<boolean>}
   */
  async doRegUnreg(type, node, challenge, challengeResponse, ip, port) {
    node = parseInt(node);

    let data = {
      node: node,
      secret: challengeResponse,
      challenge: challenge,
      port: port,
      ipaddr: ip,
      regseconds: Math.floor(Date.now() / 1000)
    };

    let response;

    try {
      if (type === 0) {
        response = await Axios.patch(node, data);
      } else {
        response = await Axios.delete(node, data);
      }
      
      return response;
    } catch (e) {
      if (e.response && e.response.status === 403 && e.response.data === 'noisy') {
        return false;
      }
    }
  }
}

module.exports = RegisterApi;
