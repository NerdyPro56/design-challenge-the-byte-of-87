#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

def print_hex(data): # data to hex conversion for utility
    hex_string = " ".join(format(byte, "02x") for byte in data)
    print(hex_string) # print string
