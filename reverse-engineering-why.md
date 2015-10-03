# Why Reverse Engineer?

There are always reasons why you need to know more about the software
that your code interacts with than its authors are willing or able to
tell you.

You may just want a more fully rounded understanding of a particular
programming environment, or set of APIs, than its documentation
provides.  However there are usually much more concrete reasons.  And
in any case it's difficult to justify spending the time needed to
"know something better".  So though this is probably the most
important goal of any programmer's professional life, it tends to get
fulfilled around the edges of more concrete tasks.

One example is a crash or other problem that you know happens in
second or third party code (in some part of the OS or in a plugin, for
example), but for which there is (as yet) no conclusive proof that the
2nd or 3rd party is at fault.  If you can't show that the problem
"belongs" to the other party, they're very unlikely to do anything
about it.  And that the problem happens in "their" code means that
knowledge of "your" code, by itself, is usually not enough to either
track down the (possible) cause in "your" code, or to prove that
"your" code can't possibly be at fault.

Problems of this nature tend to get shunted aside.  But sometimes
they're so serious (or effect so many people) that it'd be
irresponsible not to try to resolve them.

Another example is that you need to get second or third party code to
do something for which there is no documented support.  In some cases
this is accidental -- the other party never anticipated that one of
its software "clients" would need to perform "task X".  Sometimes it's
deliberate but not malicious -- the other party doesn't think that any
client should ever need to perform "task X".  Sometimes it's both
deliberate **and** malicious -- the other party wants **it's**
"clients" to have the advantage of using certain functionality that's
not available to other "clients", or not yet available.

In all of these cases (but especially the last one) there are
legitimate reasons to want to get around the other party's lack of
explicit support.  All programs above a certain level of complexity
tend to have needs that exceed what can be provided by any particular
set of documented APIs.  And an OS vendor (for example) shouldn't be
allowed to have the last word on what's "acceptable" behavior in an
app that runs on its OS.

That said, there are limits beyond which it's not wise to go in the
use of undocumented APIs, or in depending on undocumented behavior.

First (and most obviously), the required functionality shouldn't
already be available using a documented API.  Second, the
functionality needs to actually be available from the other party's
software in usable form (even if undocumented).  Third, it should be
something that the other party relies on for its "own" purposes (for
example that an OS vendor relies upon for its own apps), and which has
gone unchanged for the last few major releases.  That makes it less
likely that the other party will change its undocumented behavior
after you've chosen to rely on it.

Yet another reason to use reverse engineering is to deal with one of
the possible consquences of my first reason for using it.  Let's say
you've proved (by whatever means) that a problem is caused by a second
or third party, but they refuse to fix it -- either at all or in a
timely fashion.

Usually you just hack workarounds for these problems into your code.
All software of any practical use is littered with examples of this.

But sometimes it's actually possible to reach into the other party's
software, by hooking its methods, and fix these problems yourself.
It's often quite easy to perform this kind of "surgery" on Objective-C
code, where you can use method swizzling.  But it's also possible
(though more difficult) to hook C/C++ methods.

The same warnings apply to this as to "ordinary" use of undocumented
APIs or reliance on undocumented behavior.  But the problem that
you're fixing in the other party's code also needs to be quite simple
and self-contained -- for example a failure to retain a
reference-counted object.
