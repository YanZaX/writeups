# Barbhack 2023 - Tchoutchou 🚅

**Category:** : Web - Hard
**Description:** : 


```
   OO O o o o...      ______________________ _________________
  O     ____          |                    | |               |
 ][_n_i_| (   ooo___  |       I LOVE       | |     CME <3    |
(__________|_[______]_|____________________|_|_______________|
  0--0--0      0  0      0       0     0        0        0
```

We are also provided the following files : 

```
/home/demoniac/myapp$ bundle install
/home/demoniac/myapp$ rails s -b 0.0.0.0 -e production
```

Flag is located in a random folder on /home/demoniac/xxxxxxx/flag.txt where xxxxxxxxx is a random string.

Crontab
```
# restart rails and regenerate rails credentails (it takes long time)
*/3 * * * * /home/demoniac/restart.sh
```

## Write Up 📝

### 1 - Understanding the challenge 🧠

The application itself, doesn't show anything beside this little train is ASCI. I tried to poke around but without any success first.  
After googling a bit on "Ruby On Rails" vulnerabilities, since we know that the application run with rails, we can quickly find this repository : [https://github.com/mpgn/Rails-doubletap-RCE ](https://github.com/mpgn/Rails-doubletap-RCE)

> Fun fact, MPGN is actually the creator of this challenge !

If you read the whole Github project, the attack is nicely explained : 

1. The exploit check if the Rails application is vulnerable to the CVE-2019-5418
2. Then gets the content of the files: `credentials.yml.enc` and `master.key`
3. Decrypt the credentials.yml.enc and get the secret_key_base value
4. Craft a request to the ressource `/rails/active_storage/disk/:encoded_key/*filename(.:format)`` => CVE-2019-5420
5. Send the request to the vulnerable server
6. The code is executed on the server

### 2 - CVE-2019-5418 

The first step is to test if the application is vulnerable to CVE-2019-5418, which is a LFI via a specific crafted header, you can find a technical blog on this CVE here : [https://zhuzhuuu.com/pentesting-lab/2019-04/](https://zhuzhuuu.com/pentesting-lab/2019-04/)  
Let's test it on our challenge : 

{images/2023-08-28_20-33.png}