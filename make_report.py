import sys
import os
from os.path import join 

os.chdir(sys.argv[1])
out = open('index.html', 'w')

def split_by_rountine(lines):
    reports = []
    title = ""
    value = 0
    content = []
    for line in lines:
        if line.startswith("ROUTINE ====="):
            if content:
                reports.append((value, title, content))
            title = line.split()[2]
            content = []
            value = -1
        elif line.strip().endswith("% of Total"):
            value = float(line.split()[-3][:-1])
        else:
            content.append(line)
    if content:
        reports.append((value, title, content))
    reports.sort(key=lambda x: x[0], reverse=True)
    return reports

def m():
    print "<h2>CPU Profile</h2>"
    print """<a href="cpu.svg">SVG</a>"""
    with open('cpu.txt') as f:
        lines = f.readlines()
        print """<pre class="prettyprint">"""
        for line in lines[:min(20, len(lines))]:
            print line,
        print "</pre>"
    with open('cpu-cum.txt') as f:
        lines = f.readlines()
        print """<pre class="prettyprint">"""
        for line in lines[:min(20, len(lines))]:
            print line,
        print "</pre>"
    with open('cpu.list') as f:
        for rountine in split_by_rountine(f)[:5]:
            print "<h3>", rountine[0], "% ", rountine[1], "</h3>"
            print """<pre class="prettyprint">"""
            for line in rountine[2]:
                print line,
            print "</pre>"

    print "<h2>MEM Profile</h2>"
    print """<a href="mem.svg">SVG</a>"""
    with open('mem.txt') as f:
        lines = f.readlines()
        print """<pre class="prettyprint">"""
        for line in lines[:min(20, len(lines))]:
            print line,
        print "</pre>"
    with open('mem-cum.txt') as f:
        lines = f.readlines()
        print """<pre class="prettyprint">"""
        for line in lines[:min(20, len(lines))]:
            print line,
        print "</pre>"
    with open('mem.list') as f:
        for rountine in split_by_rountine(f)[:5]:
            print "<h3>", rountine[0], "% ", rountine[1], "</h3>"
            print """<pre class="prettyprint">"""
            for line in rountine[2]:
                print line,
            print "</pre>"

    print "<h2>BLOCK Profile</h2>"
    print """<a href="block.svg">SVG</a>"""
    with open('block.txt') as f:
        lines = f.readlines()
        print """<pre class="prettyprint">"""
        for line in lines[:min(20, len(lines))]:
            print line,
        print "</pre>"
    with open('block-cum.txt') as f:
        lines = f.readlines()
        print """<pre class="prettyprint">"""
        for line in lines[:min(20, len(lines))]:
            print line,
        print "</pre>"
    with open('block.list') as f:
        for rountine in split_by_rountine(f)[:5]:
            print "<h3>", rountine[0], "% ", rountine[1], "</h3>"
            print """<pre class="prettyprint">"""
            for line in rountine[2]:
                print line,
            print "</pre>"

if __name__ == '__main__':
    print """
<!DOCTYPE HTML>
<html>
<head>
</head>
<body>
    """
    m()
    print """
</body>
<script src="https://cdn.rawgit.com/google/code-prettify/master/loader/run_prettify.js"></script>
<html>
    """
