/** 
 * @author:Akshay Misal
 * @version:0.2
 * @since:03-Aug-2018
*/
var server = require('./../server/server')
var assert = require('assert');
var chai = require('chai');
var chaiHttp = require('chai-http');
var should = chai.should();

chai.use(chaiHttp);

//===============svr.login.js=============================================================

/**
 * @author:Akshay Misal
 * @link:GET http://localhost:8082/api/authenticate
 * @param {appName, username, password} req 
 * @param {token} res 
 * @description: authenticate user.
 */
describe('Authenticate user', () => {
    it('it should authenticate user details', (done) => {

        var data = {
            "appName": "SCF",
            "username": "buyer1234",
            "password": "123"
        }

        chai.request(server)
            .post('/api/authenticate')
            .send(data)
            .end((err, res) => {
                res.should.be.json;
                res.body.should.have.property('token');
                res.should.have.status(200);
                done();
            });
    });
});


/**
 * @author Akshay Misal
 * @link: POST http://localhost:8082/api/getUser
 * @description get user details 
 * @param {appName,username} req 
 * @param {JSONObject} res 
 */
describe('Get user details', () => {
    it('it should GET user details', (done) => {

        var data = {
            "appName": "SCF",
            "username": "buyer1234"
        }

        chai.request(server)
            .post('/api/getUser')
            .send(data)
            .end((err, res) => {
                res.should.be.json;
                res.body.should.have.property('username');
                res.should.have.status(200);
                done();
            });
    });
});

