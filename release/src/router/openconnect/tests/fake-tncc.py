#!/usr/bin/env python3
#
# Copyright © 2021 Joachim Kuebart <joachim.kuebart@gmail.com>
#
# This file is part of openconnect.
#
# This is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License
# as published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

import os


def main():
    """
    Reply "success" when we receive "hostchecker".
    """
    io = os.fdopen(0, "r+b", buffering=0)
    started = False
    for line in io:
        line = line.decode("ascii").rstrip()
        if line == "start":
            started = True
        if started and line == "Cookie=hostchecker":
            io.write(b"200\n3\nsuccess\n\n\n")
            started = False


if __name__ == "__main__":
    main()
