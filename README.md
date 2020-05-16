
Password Complexity Check
=========================

# Using Permutations to Validate Password Complexity

While studying for a Data Science course I became intrigued with the idea of using permutations as part of a password strength checking routine.

The idea is that password strength should be calculated by the number of permutations possible within a keyspace.

For instance, using only the lower case English alphabet of 26 characters, there are approximately 1.9 x 10^13 possible 10 character words that may be made.

While 10 characters is good, more is better.

Let's say you decide your passwords should all be a mix of upper and lower case English letters.
(Please, don't use dictionary words, names, etc)

The 10 character password 'thisisten' is one of approximately 1.3 * 10^15 passwords that could be formed in 10 characters.

By adding only 2 letters - 'hereStwelve', the order of complexity has increased by 3 orders of magnitude, to ~ 2.4 * 10^18.

However long it may take to crack your 10 character password, the 12 character password will take 1800 times as long.

Let's say there is a system that can crack 1 Trillion passwords per second.

This is not impossible, and may well have been done.

This article from 2012 describes a system that could make 350 Billion (350 x 10^9) guesses per second.

[25-GPU cluster cracks every standard Windows password in <6 hours](https://arstechnica.com/information-technology/2012/12/25-gpu-cluster-cracks-every-standard-windows-password-in-6-hours/)

Given the estimate of 1 Trillion guesses per second, a 12 letter password of upper and lower English characters could be brute forced in 27 days or less.


Assuming of course that the password is not discovered in a few seconds by using some of the extensive lists of known passwords for comparison.

So while 12 letters of upper and lower characters is theortically, it could be cracked.

Again, assuming password is not something easily guessed from a list of known passwords, few individuals will have the resources to crack many passwords at that rate.
 

Even so, I suspect it may be difficult to form a 12 letter password (other than random characters) that does not already appear in some of the more well known password lists.

So, longer is better.

This is where something that is more like a phrase comes into play.

For instance: my-Tesla-says-Ohm

That is only one of 1.13 * 10^32 possible combinatons.

A brute force method will require quite a long time; approximately 3.6 x 10^22 centuries.

Or put another way, 3,601,956,494,165.4 Trillion years.

## Other Considerations

As mentioned previously, there extensive lists of known passwords.

If your password appears on any of those lists, it can be cracked in a short time.

There are more considerations than I can consider here.  I am not a security expert, just curious.

There is a chance I will incorporate this technique into a password checking function for Oracle Databases, as that would be kind of fun.













