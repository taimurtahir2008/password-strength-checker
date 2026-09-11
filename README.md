what it does: 

It checks two things. First, whether a password is strong (long enough, mix of upper/lowercase, numbers, symbols, not a common weak password). Second, whether that password has shown up in a real database of known data breaches.

the privacy technique (k-anonymity): 

The tool never sends your actual password to the internet. It hashes it first (scrambles it into a fixed code using SHA-1), then only sends the first 5 characters of that scrambled code to the breach-checking service. The service sends back a list of possible matches, and your computer checks locally whether your full scrambled code is in that list. So the real password, and even the full scrambled version of it, never leaves your machine.

how to run it: 

Someone runs python3 password_checker.py in a terminal, then types a password when asked. Nothing gets saved anywhere.

why you built it: 

Combines your two interests (software engineering and cyber security) in one project, using a real security concept rather than just theory.
