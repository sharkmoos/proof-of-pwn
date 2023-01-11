# Rings of Pwn: Documentation

## Overview

The premise of the challenge is simple. You will be provided a binary (or number of binaries) in a ZIP file on port 4750, 
download it and work out how to exploit locally. Once you have a working exploit, exploit the remote binary hosted on the 
challenge server to achieve RCE, and collect the stage code string in the `stage_code` file. 
Submitting the stage code to the challenge handler will deploy the next binary for you to exploit remotely. There 
are a number of stages, at the end of each stage the challenge handler will provide you with a flag. After completing 
a stage, return to port 4750 to download the new binary ZIP.

## Interfaces

- Client Server: Port 8888
- Challenge Server: Port 9999
- Binary Server: Port 4750

## Binary Server

I'll be honest, this interface is pretty janky. The serves the file directly through the request. So no, don't bruteforce
the interface and think you've found loads of hidden challenges, because all the URLs will serve the same file e.g:

```bash
wget http://<server_ip>:4750/level.zip
wget http://<server_ip>:4750/level1.zip
```

**Hint**: This can actually be quite useful, as you can basically decide the file name based on the endpoint you enter.

## Challenge Handler 

### Connecting

Upon connecting to the client server, you should see output looking like this:

```
##############################
######  Rings of Pwn    ######
##############################


Progress: 0/1


- Enter the string `reset` to set the progress to zero.
- Enter a stage code to progress.
- Make sure you've read the CTFd instructions before you start!
Stage Code:
```

The progress figure shows how many levels you have completed. This should help you identify which code to submit next,
and confirm that the binary being server by the challenge handler is the correct one.

After obtaining a stage code, submitting it to the client will deploy the next binary on the challenge server for you to exploit.

### Completing a Stage

After completing all challenges in a stage, the challenge handler will provide you with a flag. It will look something
like this.

```
##############################
######  Heart of Pwn    ######
##############################


Progress: X/XX

Well done! You earned a flag: cueh{XXXXXXXXX}
Head back over to port 4750 to get the next challenge zip!

Loading level X
Stage Code:
```

### Resetting Progress

If you want to reset your progress, you can do so by sending `reset` to the challenge handler. This 
will set your progress to 0 and load level 0 into the challenge server. Unfortunately, currently the server does
not update the binary ZIP being served after a reset. If you need to redownload the files, restart the challenge.


## Challenge Server


The challenge server is where you should exploit the remote version of the binary. The server is running on port 9999.
After achieving RCE, grab the stage code from the `stage_code` file and submit it to the challenge handler.

When connecting to the challenge server, you should receive some output the contains the level number. 

```bash
nc 127.0.0.1 9999
Welcome to: Challenge: 0
FOOBAR!
You lose!
```

After exploiting the challenge and submitting the stage code to the challenge handler, reconnecting to this server
should show the next level number.

```bash
 nc 127.0.0.1 9999
Welcome to: Challenge: 1
FOOBAR!
You lose!
```