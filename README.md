[![42-256.png](https://i.imgur.com/Puz7qbV.png)](https://t.me/chat42coin)


42-coin - a PoW/PoS based cryptocurrency.
		
Specifications
--------------

- Max money: 42 coins
- Transaction confirmation method: PoW+POS
- Transaction type: public & private
- Number of transaction confirmation: 7
- Number of block confirmation: 42
- PoW algo type: Scrypt
- PoW reward: 0 coin + tx fees
- PoW target spacing: 21 minutes
- PoS reward: 0 coin & destroy tx fees (for deflation)
- Min stake age: 42 hours
- Max stake age: unlimited
- PoS target spacing: 7 minutes
- Default Listen Port: 4242 (42420 for testnet)
- JSON-RPC Port: 2121 (21210 for testnet)


Intro
===========================
42 is the original 42-coin client and it builds the backbone of the
network. It downloads and, by default, stores the entire history of
42-coin transactions, which requires a few hundred megabytes of disk
space.

Depending on the speed of your computer and network connection, the
synchronization process can take anywhere from a few minutes to a hour
or more.

To download 42, visit [42-coin.org](https://42-coin.org/#download).


Development process
===========================

Developers work in their own trees, then submit pull requests when
they think their feature or bug fix is ready.

The patch will be accepted if there is broad consensus that it is a
good thing.  Developers should expect to rework and resubmit patches
if they don't match the project's coding conventions (see coding.txt)
or are controversial.

The master branch is regularly built and tested, but is not guaranteed
to be completely stable. Tags are regularly created to indicate new
official, stable release versions of 42.

Feature branches are created when there are major new features being
worked on by several people.

From time to time a pull request will become outdated. If this occurs, and
the pull is no longer automatically mergeable; a comment on the pull will
be used to issue a warning of closure. The pull will be closed 15 days
after the warning if action is not taken by the author. Pull requests closed
in this manner will have their corresponding issue labeled 'stagnant'.

Issues with no commits will be given a similar warning, and closed after
15 days from their last activity. Issues closed in this manner will be 
labeled 'stale'.
