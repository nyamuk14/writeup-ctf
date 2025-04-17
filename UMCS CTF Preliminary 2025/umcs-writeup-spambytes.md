# UMCS CTF Preliminary 2025 Writeup - SpamBytes

Welcome to our writeup for the UMCS CTF Preliminary 2025!

## Table of Contents

### Forensic
1. [Hidden in Plain Graphic (Nyamuk)](#hidden-in-plain-graphic-nyamuk)

### Steganography
1. [Broken (Akmlaff)](#broken-akmlaff)
2. [Hotline Miami (Akmlaff)](#hotline-miami-akmlaff)

### Reverse Engineering
1. [Http-Server (Akmlaff)](#http-server-akmlaff)

### Cryptography
1. [Gist of Samuel (lkhwn.nzm & Akmlaff)](#gist-of-samuel-lkhwnnzm--akmlaff)

### Pwn
1. [babysc (lkhwn.nzm)](#babysc-lkhwnnzm)
2. [Liveleak (lkhwn.nzm)](#liveleak-lkhwnnzm)

### Web
1. [Healthcheck (lkhwn.nzm)](#healthcheck-lkhwnnzm)
2. [Straightforward (Nyamuk)](#straightforward-nyamuk)

## Forensic
### Hidden in Plain Graphic (Nyamuk)

### Description
> Agent Ali, who are secretly a spy from Malaysia has been communicate with others spy from all around the world using secret technique. Intelligence agencies have been monitoring his activities, but so far, no clear evidence of his communications has surfaced. Can you find any suspicious traffic in this file?

`plain_zight.pcap`

---

### Solution

First, I opened the packet capture to see what protocols were inside.  
Next, I filtered `http` protocol — maybe there were some files I could export.

![Wireshark Protocol View](img/pcapfile.png)

Unfortunately, no downloadable files were available via `http`.

![HTTP Export Window](img/exporthttp.png)

I found nothing.

Then, I tried looking for any hidden content inside the `.pcap` using `binwalk`:

```bash
binwalk -e plain_zight.pcap
```
![Binwalk -e](img/binwalk.png)

From the scan, I saw that there was a PNG file detected at offset `0x10DF1` (in decimal is `69105`).

Then, I decided to manually extract it using `dd`:

```bash
dd if=plain_zight.pcap of=manual_extracted.png bs=1 skip=69105
```

![Manual Extraction DD](img/dd.png)

The image was successfully extracted:

![img](img/manual_extracted.png)

After extracting, I checked the file type using:

```bash
file manual_extracted.png
```

![File type](img/filetype.png)

It confirmed that the image is a valid `PNG`, `512x512 RGBA` — likely suitable for steganalysis.

So, my assumption for png file, I can use `zsteg` or [aperisolve](https://www.aperisolve.com/).
Lastly, I ran `zsteg` to analyze the LSB (Least Significant Bit) layers:

```bash
zsteg manual_extracted.png
```

![Flag](img/flag.png)

Flag: **umcs{h1dd3n_1n_png_st3g}**

## Steganography
### Broken (Akmlaff)

### Description
> Can you fix what’s broken ?

`Broken.mp4`

---

### Solution

![MP4 Broken](img/mp4.png)

We cant see the video because it is broken and after using `exiftool`, checked for its `hex` and everything was okay so I just thought that the `mp4` was really broken so.

![Flag](img/flag1.png)

I searched for an online `mp4` repair tool [EaseUS](https://repair.easeus.com/#upload) put the bad boy in to repair the broken file and boom ! we got the flag.

Flag: **umcs{h1dd3n_1n_fr4me}**

### Hotline Miami (Akmlaff)
### Description
**Challenge URL:** [Github - Hotline_Miami](https://github.com/umcybersec/umcs_preliminary/tree/main/stego-Hotline_Miami)

> You’ve intercepted a mysterious floppy disk labeled 50 BLESSINGS, left behind by a shadowy figure in a rooster mask. The disk contains a cryptic image and a garbled audio file. Rumor has it the message reveals the location of a hidden safehouse tied to the 1989 Miami incident. Decrypt the clues before the Russians trace your signal.

`iamthekidyouknowwhatimean.wav`,`requirement.txt`,`rooster.jpg`

---

### Solution

`requirement.txt`:

![textfile](img/readme.png)

Saw this in the readme.txt and I was like this might be the format.

Flag format would be: **Subject_Be_Verb_Year**

`iamthekidyouknowwhatimean.wav`

![mp3](img/mp3.png)

The `.wav` file played a consistent beat. I loaded the audio into [Sonic Visualiser](https://www.audacityteam.org/), added a spectrogram layer and this appeared:

![Spectogram](img/spectogram.png)

So, we got the last 2 parts of the flag which are **WATCHING** (verb) and **1989** (year).

Next, I used [aperisolve](https://www.aperisolve.com/) on `rooster.jpg`.

![Rooster image](img/rooster.png)

![Aperisolve image](img/aperisolve.png)

It’s a hot nugget and when I scrolled down until the end of the string I saw **Richard** and it was actually a character in hotline miami game. So, I think that’s the subject?

![Reddit image](img/reddit.png)

![Richard image](img/Richard.png)

Then I was googling I saw this reddit post that says the game was just Richard watching a film and I also that he is connected to the 1989 killing on fandom so I think its making sense?

So, I put **the Subject_Be_Verb_Year** from the `requiement.txt` and all the hints I got **Watching** ,**1989** and **Richard**. Then... voila!!

![Flag](img/flag2.png)

Flag: **umcs{Richard_Is_Watching_1989}**

## Reverse Engineering

### Http-Server (Akmlaff)
### Description
> I created a http server during my free time
> 
> 34.133.69.112 port 8080

`server.unknown`

---

### Solution

We got a file named `server.unknown`.

![Filetype](img/serverunknown.png)

Downloaded the file and checked for the file type and it was an `ELF` file so I put it into my bestfriend chatgpt instead of trying the **nc 34.133.69.112 8080**.

![Chat GPT](img/gpt.png)

So uh… this wasn’t any interesting but after I having a very very deeptalk with my brother **chatpgt** and I used the
```bash
printf "GET /goodshit/umcs_server HTTP/13.37\r\n\r\n" | nc 34.133.69.112 8080
```
and… I don’t know if this was intended or not but… chatgpt was explaining the 500 error and it asked me to test forging the raw `HTTP` request and… I guess…

![Flag](img/flag3.png)

I got the flag...!! yay.

Flag: **umcs{http_server_a058712ff1da79c9c9bbf211907c65a5cd}**

## Cryptography

### Gist of Samuel (lkhwn.nzm & Akmlaff)
### Description
> Samuel is gatekeeping his favourite campsite. We found his note.
> 
> flag: umcs{the_name_of_the_campsite}
> 
> The flag is case insensitive

<details>
  <summary>Hint for 0 points</summary>
! This is not a real hint. ! I dont remember but, its a another gist hash of umcs
</details>

`gist_of_samuel.txt`

---

### Solution

![Content of gist_of_samuel.txt](img/train.png)

We were given a file full of train emojis.

From the pattern, the blue train is always singular, so we instantly assume it was morse code since the spaces are required to separate the characters.

![Script gpt](img/morsecodescript.png)

We used gpt to generate a script to convert it into dots and dash.

![Decode Morsecode](img/decodemorse.png)

Then we used multiple morse code decoders online to decrypt it. But not of all it works as not all morse code decoders has `#`. 
We initially thought `E012D0A1FFFAC42D6AAE00C54078AD3E` is a md5 hash and it needs to be decrypted. But no encryption we tried worked. So I was stucked here for a while.

![Hint Gist Hash](img/hint.png)

Then, the admin released a hint here and instantly we knew the string earlier wasn’t an encrypted value but an address of another github page. So we pasted the hash on the url.

```bash
https://gist.github.com/umcybersec/e012d0a1fffac42d6aae00c54078ad3e
```

![Gist Hash](img/gist.png)

And we got the **veryveryveryverysecret**.

![Rail Fence Cipher](img/railfencecipher.png)

Then we tried the only thing left that relates to trains because Samuel is obsessed with trains. **Rail fence**, because it rhymes
With railway. We also use number **8** as the key because the morse code also translates to Samuel favourite number is 8.

Then, seeing this is usually used as ascii art, we thought that maybe the text needs to be within a specific width to be something readable.

![Output1](img/output1.png)

![Output2](img/output2.png)

![Flag](img/flag4.png)

After making it wider we got the flag!!

Flag: **umsc{WILLOW_TREE_CAMPSITE}**

## PWN

### babysc (lkhwn.nzm)
### Description
> shellcode
> 
> 34.133.69.112 port 10001

`Dockerfile`, `babysc.c`, `babysc`










