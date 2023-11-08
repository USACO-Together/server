"""
MIT License

Copyright (c) 2023 Oviyan Gandhi

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

class APIException(Exception):
    def __init__(self, status_code: int, errors: list[dict]):
        self.status_code = status_code
        self.errors = errors

class NotConnectedError(Exception):
    def __init__(self):
        super().__init__("Connection has not been made to the database")

class UnauthorizedError(Exception):
    def __init__(self):
        super().__init__("You are not authorized to access this resource")

class DuplicateError(Exception):
    def __init__(self):
        super().__init__(f"Duplicate value(s) provided")

class UnknownUsernameError(Exception):
    def __init__(self, username: str):
        super().__init__(f"Unknown username '{username}'")