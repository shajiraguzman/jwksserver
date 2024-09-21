# Shajira Guzman

import unittest
from server import app, keys  # importing app from server.py
import json



class TestApp(unittest.TestCase):

    # client for the flask application
    def setUp(self):

        self.app = app.test_client()
        self.app.testing = True 


    # test the JWKS endpoint
    def testEndpoint(self):

        response = self.app.get('/.well-known/jwks.json')
        self.assertEqual(response.status_code, 200)  # checks for OK response
        json_data = json.loads(response.data)        # convert to JSON


    # test the auth endpoint with valid parameters
    def testAuthValid(self):

        response = self.app.post('/auth')
        self.assertEqual(response.status_code, 200)  # checks for OK response
        json_data = json.loads(response.data) 
        self.assertIn('token', json_data)            # checks for token


    # test the auth endpoint with expired parameters
    def testAuthExpired(self):

        response = self.app.post('/auth?expired=true')
        self.assertEqual(response.status_code, 200)
        json_data = json.loads(response.data)
        self.assertIn('token', json_data)  


if __name__ == '__main__':
    app.run(port=8080)