# Copyright (C) 2016 Johnny Vestergaard <jkv@unixcluster.dk>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import unittest
from datetime import datetime

from beeswarm.shared.misc.time import isoformatToDatetime


class TimeTests(unittest.TestCase):
    def test_isoFormatToDateTime(self):

        no_microseconds = datetime(2016, 11, 12, 11, 47, 20, 0)
        no_microseconds_isoformat = no_microseconds.isoformat()
        self.assertEquals(isoformatToDatetime(no_microseconds_isoformat), no_microseconds)

        has_microseconds = datetime(2016, 11, 12, 11, 47, 20, 4242)
        has_microseconds_isoformat = has_microseconds.isoformat()
        self.assertEquals(isoformatToDatetime(has_microseconds_isoformat), has_microseconds)
