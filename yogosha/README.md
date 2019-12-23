# Yogosha - Christmas Challenge

**Category:** Mostly Web
**Description:**

> The first hint we are given is the following tweet : 
[Find It](https://twitter.com/YogoshaOfficial/status/1206565805372121088)


## Write-up

### First Step - Find the target
I started to analyse the picture from the tweet but it didn't lead to anything so I browsed twitter looking for *#yogoshachristmaschallenge* and I found this post :

![Hint](https://raw.githubusercontent.com/YanZaX/writeups/master/yogosha/images/2019-12-23_16h24_24.png)

Cuttly is an URL shorter and we probably need to find the shortened link. Let's focus on the second hint : 

The following hash : "3f5089c0f9f45530f48aa03471f473ff0af999557bf78749d6d5de6c6b39632b" looks like SHA256, so let's try to decode it : 

![Decode Hash](https://raw.githubusercontent.com/YanZaX/writeups/master/yogosha/images/2019-12-23_16h31_08.png) 

Cool ! We got a result, now let's browse http://cutt.ly/09031980 which redirect to http://3.19.111.121/

![Second Step](https://raw.githubusercontent.com/YanZaX/writeups/master/yogosha/images/2019-12-23_16h33_54.png)

### Second Step - Find an entry point

Let's run a full port scan against the server, we found the following open ports :

![open ports](https://raw.githubusercontent.com/YanZaX/writeups/master/yogosha/images/2019-12-23_16h48_43.png)

Okay, port 1337 is open and it looks really interesting for a CTF ! Let's see what's behind !

![pwn](https://raw.githubusercontent.com/YanZaX/writeups/master/yogosha/images/2019-12-23_16h38_43.png)

We have a prompt waiting for a secret code ... I started trying to send (a lot) of junk data, I started to wondering how could I exploit this program blindly. Maybe it's time-based ? The program might not be well implemented and could process take more times to process valid char ?!

I found a script wrote by [Sakiir](https://twitter.com/sakiirsecurity) which is doing exactly what I wanted : https://github.com/SakiiR/timeauth 

I obviously had to customize the script but after few minutes I got the following result : 

![pwned](https://raw.githubusercontent.com/YanZaX/writeups/master/yogosha/images/2019-12-23_18h24_07.png)

I logged with the password : **pAsSwOrd159!** and after few retries I found an interesting user : **noel (you)**

![logged](https://raw.githubusercontent.com/YanZaX/writeups/master/yogosha/images/2019-12-23_16h51_56.png)

### Third Step - Pivoting and exploiting alternatives services

I didn't mentioned it, but while I was scanning ports, I did some recon against the webserver and noticed that it was a wordpress and the login page was available : 

* http://3.19.111.121/wp-login.php

* I was also able to browse all posts by browsing the WordPress API :  http://3.19.111.121/?rest_route=/wp/v2/posts/ notice that /wp-json/ was restricted.

So let's try to use the credentials we found earlier on this login form ! 
It worked but we are immediatly redirected to the home page, it looks like the admin interface is disabled ! 

We had to find another way so I started to bruteforce in order to find common wordpress plugin and I found a directory listing under http://3.19.111.121/wp-content/plugins/.

Under the ACF (Advanced Custom Fields) folder, I found a zip file that looks like the latest version of ACF and probably the one running on this wordpress.

I went on the ACF website and downloaded the same version : https://www.advancedcustomfields.com/downloads/

![ACF](https://raw.githubusercontent.com/YanZaX/writeups/master/yogosha/images/2019-12-23_17h17_38.png)

Then I did a diff between the two folders : 

![DIFF](https://raw.githubusercontent.com/YanZaX/writeups/master/yogosha/images/2019-12-23_17h21_14.png)

I found this piece of code quite interesting, after digging inside the source I was able to understand what it does : 

* If logged with the user *noel* and if the parameter *debug* is set to 1 then the parameter *upd* is called.
* The parameter *udp* is used to make a request and is printed on the page.

Okay it looks like we got an SSRF (Server Side Request Forgery), let's see if I can reach a burp collaborator instance : 

![burp collaborator](https://raw.githubusercontent.com/YanZaX/writeups/master/yogosha/images/2019-12-23_17h33_46.png)

Cool it worked ! let's try to find something interesting browsable only from localhost : 

I ran a quick burp intruder and found that **server-status** was available !

![server-status](https://raw.githubusercontent.com/YanZaX/writeups/master/yogosha/images/2019-12-23_17h30_44.png)

I guess the challenge is not over, the next step is leading us to the darknet.

###  Fourth Step - The Dark Net

Let's head to the website : http://bacq7ip6nzdyhb3o.onion

![darknet](https://raw.githubusercontent.com/YanZaX/writeups/master/yogosha/images/2019-12-23_17h39_59.png)

Before starting to dig on the login form, I tried to trigger an error in order to find the real IP and it worked : 

![realIP](https://raw.githubusercontent.com/YanZaX/writeups/master/yogosha/images/2019-12-23_17h40_19.png)

We have our new target, after playing around the login form I quickly noticed interesting verbose errors : 

![xpath](https://raw.githubusercontent.com/YanZaX/writeups/master/yogosha/images/2019-12-23_17h41_54.png)

Yes, we probably have XPath injection here ! We are guessing that we probably have something like this in the backend : 
```
$xpath = "//user[user='" . $_POST['user'] . "' and password='" . $_POST['pass'] . "']";
```
 
So let's use **' or '1'='1** on the user and password field to craft the following query :

```
$xpath = "//user[user='' or '1'='1' and pass='' or '1'='1']";
```

And it worked ! We are logged as admin and have access to this interesting page : 

![logged](https://raw.githubusercontent.com/YanZaX/writeups/master/yogosha/images/2019-12-23_17h47_18.png)

We keep note of the internal IP address which might be our next target. The page also indicate a txt file containing some juicy notes from a hacker : http://3.13.238.49/b%C4%81Ckup%C4%93/Target/172.28.13.37/payload/hack.txt 

![notes](https://raw.githubusercontent.com/YanZaX/writeups/master/yogosha/images/2019-12-23_17h49_27.png)

> The server was just using another container to back up and access its data

### Last Step - Pwn the backup server

Let's use our previous SSRF to find an open port on the new target. After scanning all ports, I found out that port 3306 (mysql) and 80 (http) was open !
Let's see what's available on port 80 :

![Backup](https://raw.githubusercontent.com/YanZaX/writeups/master/yogosha/images/2019-12-23_17h57_30.png)

We have a backup server where we can force this client to connect to a mysql server of our choice. I found an interesting article which explains how we can read arbitrary files on a server by deploying a rogue mysql server :

https://lightless.me/archives/read-mysql-client-file.html

I found the following mysql rogue server available on github : https://github.com/Gifts/Rogue-MySql-Server

I quickly set up the Rogue server on my own VPS and forced the backup server to connect to my Rogue MySQL Server.
And it worked, I received all the **/etc/passwd** content in my log file and also the flag ! 

![flag](https://raw.githubusercontent.com/YanZaX/writeups/master/yogosha/images/2019-12-23_18h04_10.png)

>Yogosha{4t_christma5_all_r0ads_Le4d_hOme}
