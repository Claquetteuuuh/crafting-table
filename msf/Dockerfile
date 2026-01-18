FROM metasploitframework/metasploit-framework:latest

# Create a non-root user
RUN adduser -D -u 1000 -h /home/msfuser msfuser

# Ensure msfvenom is executable by others (usually is, but good to be sure)
# The base image installs to /usr/src/metasploit-framework
# We don't need to do anything if it's world executable.

