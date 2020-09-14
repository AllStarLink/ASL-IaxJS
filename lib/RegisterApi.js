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
        let data = {
            secret: challengeResponse,
            challenge: challenge,
            port: port,
            ipaddr: ip,
            regseconds: Math.floor(Date.now() / 1000)
        };
        
        try {
            let response;
            if (type === 0) {
                response = await Axios.patch(node, data);
            } else {
                response = await Axios.delete(node, data);
            }

            return response && response.status === 200;
        } catch (e) {
            console.error(e);
            return false;
        }
    }
}

module.exports = RegisterApi;