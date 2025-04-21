# Writeup UMassCTF 2025 (some Forensics and Misc) - NY4MUK

## Table of Contents

### Forensics
1. [No Updates](#no-updates)
2. [Macrotace](#macrotrace)

### Misc
1. [Odd One Out](#odd-one-out)
2. [Tower Signal](#tower-signal)

---

## Forensics
### No Updates

### Description
> I don't believe in updating my computer, it just takes so long! Besides, no one could ever hack me, I use good passwords!

`chall.pcapng`

---

### Solution

`chall.pcapng` overview:

![Wireshark Chall Overview](img/forensics/chall.png)

We look through the traffic and see a lot of `DNS` and `TCP` packets. There’s no `HTTP`, so we know we’ll need to dig deeper, likely a raw `TCP` shell or reverse shell session.

After serveral minutes talking with my bestfriend. gpt gave me this filter command:

```bash
frame contains "flag"
```

![Filter Command](img/forensics/filter.png)

Then, I tried to follow `TCP` stream. Maybe I can find something there?

![TCP Stream](img/forensics/flag1.png)

Found it. 

So, basically in forensics chall. Typically it consist of finding inside the files. You just can filter out for the flag. 

This is another solution:




