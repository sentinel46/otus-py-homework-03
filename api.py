#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import json
import datetime
import logging
import hashlib
import uuid
import re
from optparse import OptionParser
from http.server import HTTPServer, BaseHTTPRequestHandler

SALT = 'Otus'
ADMIN_LOGIN = 'admin'
ADMIN_SALT = '42'
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: 'Bad Request',
    FORBIDDEN: 'Forbidden',
    NOT_FOUND: 'Not Found',
    INVALID_REQUEST: 'Invalid Request',
    INTERNAL_ERROR: 'Internal Server Error',
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: 'unknown',
    MALE: 'male',
    FEMALE: 'female',
}


class CharField(object):
    def __init__(self, required=False, nullable=True):
        self.required = required
        self.nullable = nullable

    def __set__(self, instance, value):
        if value is None and (self.required or not self.nullable):
            raise AttributeError('Value is required', value)
        elif value is None and self.nullable:
            self.value = value
        else:
            self.validate(value)
            self.value = value

    def validate(self, value):
        logging.debug('validating chars')
        if not (type(value) == str):
            raise ValueError('Char Field got non-string type')


class ArgumentsField(object):
    def __init__(self, required=False, nullable=True):
        self.required = required
        self.nullable = nullable

    def __set__(self, instance, value):
        if value is None and (self.required or not self.nullable):
            raise AttributeError('Value is required', value)
        elif value is None and self.nullable:
            self.value = value
        else:
            self.validate(value)
            self.value = value

    def validate(self, value):
        logging.debug('validating arguments')


class EmailField(CharField):
    def validate(self, value):
        logging.debug('validating email')
        super().validate(value)
        regexp = r'\"?([-a-zA-Z0-9.`?{}]+@\w+\.\w+\"?'
        pattern = re.compile(regexp)
        if not re.match(pattern, value):
            raise ValueError('Email Field got not valid value')


class PhoneField(object):
    def __init__(self, required=False, nullable=True):
        self.required = required
        self.nullable = nullable

    def __set__(self, instance, value):
        if value is None and (self.required or not self.nullable):
            raise AttributeError('Value is required', value)
        elif value is None and self.nullable:
            self.value = value
        else:
            self.validate(value)
            self.value = value

    def validate(self, value):
        logging.debug('validating phone')
        value = str(value)
        if not (len(value) == 11):
            raise ValueError('Phone Field must contain 11 numbers')
        elif not value.isdigit():
            raise ValueError('Phone Field must contain only digits')
        elif not value.startswith('7'):
            raise ValueError('Phone Field must start with "7"')


class DateField(object):
    def __init__(self, required=False, nullable=True):
        self.required = required
        self.nullable = nullable

    def __set__(self, instance, value):
        if value is None and (self.required or not self.nullable):
            raise AttributeError('Value is required', value)
        elif value is None and self.nullable:
            self.value = value
        else:
            self.validate(value)
            self.value = value

    def validate(self, value):
        logging.debug('validating date')
        try:
            date = datetime.strptime(value, '%d.%m.%Y').date()
        except ValueError as e:
            raise ValueError('Date Field must be in dd.mm.yyyy format')


class BirthDayField(DateField):
    def validate(self, value):
        logging.debug('validating birthday')
        super().validate(value)
        value = datetime.strptime(value, '%d.%m.%Y').date()
        today = datetime.now().date()
        if not (today - value).days // 365 < 70:
            raise ValueError('Birthday Field must be ')


class GenderField(object):
    def __init__(self, required=False, nullable=True):
        self.required = required
        self.nullable = nullable

    def __set__(self, instance, value):
        if value is None and (self.required or not self.nullable):
            raise AttributeError('Value is required', value)
        elif value is None and self.nullable:
            self.value = value
        else:
            self.validate(value)
            self.value = value

    def validate(self, value):
        logging.debug('validating gender')
        if value not in GENDERS:
            raise ValueError('Unknown gender')


class ClientIDsField(object):
    def __init__(self, required=False, nullable=True):
        self.required = required
        self.nullable = nullable

    def __set__(self, instance, value):
        if value is None and (self.required or not self.nullable):
            raise AttributeError('Value is required', value)
        elif value is None and self.nullable:
            self.value = value
        else:
            self.validate(value)
            self.value = value

    def validate(self, value):
        logging.debug('validating client IDs')


class ClientsInterestsRequest(object):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)


class OnlineScoreRequest(object):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def validate(self):
        validating_pairs = [
            ('first_name', 'last_name'),
            ('email', 'phone'),
            ('birthday', 'gender'),
        ]


class MethodRequest(object):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512(datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).hexdigest()
    else:
        digest = hashlib.sha512(request.account + request.login + SALT).hexdigest()
    if digest == request.token:
        return True
    return False


def method_handler(request, ctx, store):
    response, code = None, None
    return response, code


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        logging.debug(f'Context: {context}')
        request = None
        try:
            logging.debug('Get data string')
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            logging.debug(f'Data string: {data_string}')
            request = json.loads(data_string)
            logging.info(f'Request: {request}')
        except Exception as e:
            logging.info(f'Request error: {e}')
            code = BAD_REQUEST

        if request:
            path = self.path.strip('/')
            logging.info(f'{self.path}: {data_string} {context["request_id"]}')
            if path in self.router:
                try:
                    response, code = self.router[path]({'body': request, 'headers': self.headers}, context, self.store)
                except Exception as e:
                    logging.exception(f'Unexpected error: {e}')
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        if code not in ERRORS:
            r = {'response': response, 'code': code}
        else:
            r = {'error': response or ERRORS.get(code, 'Unknown Error'), 'code': code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r).encode('utf-8'))
        return


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
