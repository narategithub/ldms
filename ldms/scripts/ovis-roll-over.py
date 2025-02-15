#!/usr/bin/env python3
import shlex
from subprocess import Popen, PIPE
import shutil
import sys
import argparse
import time
import os
from sosdb import Sos

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Rotate OVIS SOS Storage Containers.")

    parser.add_argument("--src_path", metavar="DB-PATH", required=True,
                        help="The directory for the current container.")
    parser.add_argument("--dst_path", metavar="DB-PATH", required=True,
                        help="The path where the current container will be archived.")

    parser.add_argument("--prev_link", metavar="DB-PATH", default="Yesterday",
                        help="The link pointing to the previous LDMSD storage subdirectory.")
    parser.add_argument("--next_link", metavar="DB-PATH", default="Today",
                        help="The link pointing to the next LDMS storage subdirectory.")
    parser.add_argument("--next_name", metavar="DB-PATH", required=True,
                        help="The name of the subdirectory in src_path where new LDMSD data will be placed.")

    parser.add_argument("--cfg_host", metavar="PORT-NO", default="localhost",
                        help="The hostname/ip-address where the ldmsd is listening.")
    parser.add_argument("--cfg_port", metavar="PORT-NO", default="413",
                        help="The port on where the ldmsd is listening.")
    parser.add_argument("--cfg_auth_file", metavar="PATH", default="/opt/ovis/etc/ldms/ldmsauth.conf",
                        help="The path to the file containing the shared secret.")

    parser.add_argument("--save", action="store_true",
                        help="Specify if old data is to be preserved.")

    args = parser.parse_args()

    # Check if auth file exists
    if not os.path.isfile(args.cfg_auth_file):
        print(f"The secret file specified, {args.cfg_auth_file}, does not exist.")
        sys.exit(1)

    # Tell the running daemon to start storing data to a new path
    #
    # args:
    #    The new storage container path
    #    The port the ldmsd is listening on for configuration connections
    #    The location of the auth file containing the shared secret
    #
    p = Popen(["/opt/ovis/bin/ldmsd_controller",
               "--host", args.cfg_host,
               "--port", args.cfg_port,
               "--auth_file", args.cfg_auth_file],
              stdin=PIPE, stdout=PIPE)
    next_path = args.src_path + "/" + args.next_name
    (out, err) = p.communicate(input="config name=store_sos path={0}\nquit".format(next_path))
    if out is not None and len(out) > 0:
        print("Failure attempting communicate with the ldmsd daemon:")
        print(f"{out}")
        sys.exit(2)
    print(f"LDMSD now storing into {next_path}")

    # If a yesterday link exists, destroy that tree and link yesterday to today
    yesterlink = args.src_path + "/" + args.prev_link
    if os.path.islink(yesterlink):
        yesterpath = os.readlink(yesterlink)
        os.unlink(yesterlink)
    else:
        yesterpath = yesterlink
    if not args.save:
        try:
            shutil.rmtree(yesterpath)
        except Exception as e:
            print("Failed to remove old data.")
            print("The error is:")
            print(f"{e}")

    #
    # Update the 'Today' link to point to the next_path
    #
    today = args.src_path + "/" + args.next_link

    # Save off the current value of 'Today' it will become 'Yesterday'
    yesterpath = os.readlink(today)
    os.unlink(today)
    os.symlink(next_path, today)
    os.symlink(yesterpath, yesterlink)

    print(f"{today} now pointing to {next_path}")
    print(f"{yesterlink} now pointing to {yesterpath}")

    # Move the contents of the previous directory to archive storage
    #   copy the container files to the destination directory
    print(f"copying {yesterpath} to {args.dst_path}... ")
    shutil.copytree(yesterpath, args.dst_path+"/"+os.path.basename(yesterpath))
    print("done")
    sys.exit(0)
