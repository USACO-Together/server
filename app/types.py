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
from pydantic import BaseModel
from typing import Literal, Optional

class User(BaseModel):
    name: str
    password: str

class OptionalUser(BaseModel):
    name: Optional[str] = None
    password: Optional[str] = None

class Progress(BaseModel):
    id: str
    lastUpdated: int
    progress: str

class ModuleProgress(Progress):
    progress: Literal["Not Started", "Reading", "Practicing", "Complete", "Skipped", "Ignored"]

class ProblemProgress(Progress):
    progress: Literal["Not Attempted", "Solving", "Solved", "Reviewing", "Skipped", "Ignored"]

class ModuleList(BaseModel):
    modules: list[ModuleProgress]

class ProblemList(BaseModel):
    problems: list[ProblemProgress]

class InitialData(BaseModel):
    modules: list[ModuleProgress]
    problems: list[ProblemProgress]

class FollowRequest(BaseModel):
    username: str