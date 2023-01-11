# Rings of Pwn

## Public Update

If you're reached this repository on GitHub, the event this challenge was written for has probably ended. I have now made 
the challenge infrastructure and an example solve script available now for educational purposes.

## Challenge

- Author: sharkmoos
- Difficulty: Medium 

> Note to testers: you need to run `docker-compose down -v` to bring down the container, otherwise the 
> named volumes persist and bad things happen next time the container is brought up.


# Author Brief

This was heavily inspired by one of the DARPA Cyber Grand Challenge (2016) problems, obviously it's a massively simplified
version and also introduces some concepts not covered in the CGC. It's essentially presenting a 
scenario where a piece of software has been identified as vulnerable to a remote code execution vulnerability, and
there are a number of versions of the program each with minor changes. The players need to exploit one program, and then
work out how to use that model to create automation which can exploit the other X number of programs.

Currently, it's not too hard. Any single binary in a CTF would barely reach the easy difficulty, but I have some ideas for more
complex versions of this problem, and I hope this will be enough of a challenge for section of the 5 day CTF.

## Level 0 

Level 0 is just a tutorial to get people used to the infra. This does not require achieving code execution, 
the challenge attempts to emulate a fuzzing scenario where simply causing memory corruption is enough. 
Hopefully the complexity of the infrastructure gives people the hint that they should be looking at solving the challenges
programmatically, though they may just do `python -c "print 'A' * 100000" | ./levelX`.

## Level 1

Moving things up a notch here, with 25 versions of the vulnerable program. Rather than just memory corruption, the 
player will need to `ret2win` to get the flag. By this point it should be obvious that the players should be programming
their solutions, and anyone familiar with pwntools ELF module or a similar symbol parser should make short work of this.

## Level 2

This is where things *start* to get interesting. The players are presented with 50 versions of the vulnerable program, 
and they need to implement a ret2plt to get code execution. This is still possibly only using pwntools, but its 
slightly more involved as it will require some automatic ROP chain generation due to the locations of the 
functions changing per binary. This should be relatively significant as the templating engine will embed different
numbers of gruff functions into the binary to spread things out.

## Level 3

Moving a step higher, the players are presented with 75 versions of the vulnerable program. A full ret2libc is required
here, and the players will need to implement a libc leak to get the flag. This will not add huge complexity to the exploit,
but it will test the methodology of the players through the additional payload and address leaking calculations 

## Level 4

This is the largest step up in difficulty, as it is multi faceted. The players are presented with 100 versions of the
binary. There is a stack cookie in each of the programs. I used angr to solve this level, it may well be possible 
using binary analysis (such as reverse taint) or another symbolic execution engine. The other prong to this challenge 
is the quality, so the players may need to use multiprocessing and memory optimisations to speed things up, depending 
on how fast they get to this stage.

[//]: # (## Level 5)
[//]: # ()
[//]: # (Level 4 was easy enough? Well, try it again but without any symbols in the binary.)


## Challenge Description (For players)

If you're religious, or you like reading, you may have heard of the levels/ rings of hell. If you can't be bothered to 
read Dante's Inferno, here is an interesting/humorous summary. Essentially things in the outer rings of hell start of 
pretty dandy, and the further you get in the more shit it gets, which is a pretty fair reflection of this challenge!

Download the documentation file ([rings_of_pwn_doc.md](./doc.md)) to get started, as the infrastructure may not be 
obvious at first.

