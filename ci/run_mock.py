#!/usr/bin/env python

import os.path
import sys
import subprocess

if __name__ == '__main__':
    major, minor, patch = sys.version_info[:3]
    print('Running with Python %d.%d.%d' %
          (major, minor, patch))
    mock = None
    if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
        mock = subprocess.Popen(('python3', sys.argv[1],),
                                stdout=subprocess.PIPE,
                                universal_newlines=True)
        bus_name = mock.stdout.readline().rstrip()
        print('Bus name set to %r' % bus_name)
    #if mock is not None:
    #    mock.terminate()
    #sys.exit(not result.wasSuccessful())
