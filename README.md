# Yogosha - Christmas Challenge

**Category:** Mostly Web
**Description:**

> The first hint we are given is the following tweet : 
![Find It](https://twitter.com/YogoshaOfficial/status/1206565805372121088/photo/1)


## Write-up

### First Step - Find the target
I started to analyse the picture from the tweet but it didn't lead to anything so I browsed twitter looking for *#yogoshachristmaschallenge* and I found this post :

![Hint](https://twitter.com/LazyPirate4/status/1206555411458994177)

Cuttly is an URL shorter and we probably need to find the shortened link. Let's focus on the second hint : 

The following hash : "3f5089c0f9f45530f48aa03471f473ff0af999557bf78749d6d5de6c6b39632b" looks like SHA256, so let's try to decode it : 

![Decode Hash](https://github.com/) 

Cool ! We got a result, now let's browse http://cutt.ly/09031980 which redirect to http://3.19.111.121/

![Second Step](https://github.com/)

### Second Step - Find an entry point

Let's run a full port scan against the server, we found the following open ports :

![open ports](https://github.com/)

Okay, port 1337 is open and it looks really interesting for a CTF ! Let's see what's behind !

![pwn](https://github.com/)

We have a prompt waiting for a secret code ... I started trying to send (a lot) of junk data, I started to wondering how could I exploit this program blindly. Maybe it's time-based ? The program might not be well implemented and could process take more times to process valid char ?!

I found a script wrote by [Sakiir](https://twitter.com/sakiirsecurity) which is doing exctacly what I wanted : https://github.com/SakiiR/timeauth 

I obviously had to customize the script but after few minutes I got the following result : 

![pwned](https://github.com/)

I logged with the password : **pAsSwOrd159!** and after few retries I found an interesting user : **noel (you)**

### Third Step - Pivoting and exploiting alternatives services

I didn't mentioned it, but while I was scanning ports, I did some 
