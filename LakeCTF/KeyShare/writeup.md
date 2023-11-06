## Keyshare

So basically in keyshare we are given an "oracle".

The oracle starts by giving us `sk * P`, where `sk` is the secret key (an integer inside `GF(p)`) and `P` which encodes the flag we want to obtain. Then the oracle gives us 4 queries, in each query we can give it some point `P_k` and it will give us back the value `sk * P_k`. From this premise, it's obvious that we want to solve for `sk` somehow. But the `P`'s aren't integers - they're point on an elliptic curve (and thru another lens, a group element)! How do we solve this?

Normally this wouldn't be breakable on a correct implementation. However, there is one flaw to the implementation - the server doesn't actually check whether the point you query to the oracle, is actually a point on the curve or not. This gives rise to something called the *invalid curve attack*.

But even if you can give the server invalid points, what good does that do? It probably just results in undefined behaviour when the server does the math or something hard to exploit cryptanalytically... right?

## Tweaking the B's

Take a look at the algebraic formulae for doing [point arithmetic](https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication). Do you notice anything special?

If you observe, nowhere in the formulas for point addition is `B` involved, which is the constant term in the elliptic curve equation `y^2 = x^3 + Ax + B`. Since point multiplication is basically just repeated point addition, the same is true for point multiplication too.

What does this mean? If we pick a different `B` to generate an "invalid curve", and then feed a point from that curve to the server, what will the server do? Since the algebraic formulae for doing the elliptic curve math is exactly the same, it turns out that the server will basically be doing the point multiplication on *our* curve. But what good is doing math on a different curve for our attack purposes?

## Discrete logs and the invalid curve

The main thing which makes certain elliptic curves useful for asymmetric crypto is the difficulty of the discrete log problem in them. The discrete log problem goes like this: You are given some elliptic curve point `P`, and you are given `y = (n * P)` where `n` is an integer. You are asked to find `n`. It turns out the best algorithms people have come up with to this problem boil down this: keep trying different values of `n`, until you get the `y` value. THere are improvements on the dumbest approach, but it still takes `O(sqrt(n))` time, where `n` is the order of the elliptic curve. Considering the elliptic curve used in the problem has an order of ~2^192, that's still 2^96 time.

So, if the number of candidate `n` values is very big, discrete log will be difficult. So, the bigger the order of P (which is equal to the order of the elliptic curve group when it is prime - if you want to learn more about this you should take an intro to modern algebra course), the harder the discrete log problem is.

So this is where our invalid curves come in. If we cleverly choose elliptic curves with composite orders, then we will be able to "mine" points inside those elliptic curves with smaller orders. Then we can trick the server into giving us `sk * P` where `P` is one of these smaller order points, and since the candidate `n` values is smaller we will able to solve the discrete log problem on these curves (although this is not the same thing as solving the discrete log problem on the bigger problem and obtaining `sk` directly as we will see).

## Cherry picking curves and points

Let's look at an example with the same curve used in the chall - P-192. Let's open up Sagemath and initialize the P-192 Elliptic Curve first:

```python
p = 0xfffffffffffffffffffffffffffffffeffffffffffffffff
a = 0xfffffffffffffffffffffffffffffffefffffffffffffffc
b = 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1
ec0 = EllipticCurve(GF(p), [a,b])
ec0
# Elliptic Curve defined by y^2 = x^3 + 6277101735386680763835789423207666416083908700390324961276*x + 2455155546008943817740293915197451784769108058161191238065 over Finite Field of size 6277101735386680763835789423207666416083908700390324961279
```

Ok now that we have our curve, let's play around with the `b` value and get ourselves one of those "invalid" curves. Let's just pick `b = 1` because why not:

```python
ec1 = EllipticCurve(GF(p), [a,1])
ec1
# Elliptic Curve defined by y^2 = x^3 + 6277101735386680763835789423207666416083908700390324961276*x + 1 over Finite Field of size 6277101735386680763835789423207666416083908700390324961279
```

Let's look at the order, more specifically its prime factorization:

```python
factor(ec1.order())
# 41 * 8123 * 586213 * 7066373093489 * 951465252363947 * 4782047835442779533
```

Ok, so our elliptic curve's order breaks down into lots of primes, some of them pretty small. What now?

It turns out that elliptic curve groups are *cyclic*. What this means is that we can take any factor `k` of the elliptic curve's order, and easily create an element that is of that order. How do we do this?

Let's say we want to make an element that is of order 41 in this case (since 41 is a factor of the elliptic curve's order). We start by finding the "generator" element, which is the point in the group that is the same order as the elliptic curve itself (since elliptic curves are cyclic). Call this element `g`.

```python
g = ec1.gen(0)
g
# (4430368525472652806609907369979345217241746908779747524865 : 3821373115362966372979773553603028631411882966194022219681 : 1)
```

`g` has the same order as the order of the group, meaning that if we multiply `ec1.order() * g` we will get back the identity element `(0, 1)` (which is the identity, in the sense that `(0, 1) + P = P` for any point `P` inside the group - think of it as the "zero" element), and that `ec1.order()` really is the smallest number larger than 0 that will get you `(0, 1)` when multiplied by `P`:

```python
g * ec1.order()
# (0 : 1 : 0)
```

What happens if we multiply `g` by all the factors of the order of the curve, except 41? We will get `8123 * 586213 * 7066373093489 * 951465252363947 * 4782047835442779533 * g` - call this `h`. It turns out that point multiplication for elliptic curves is associative - so `41 * h = 41 * 123 * 586213 * 7066373093489 * 951465252363947 * 4782047835442779533 * g = ec1.order() * g = (0, 1)`. So then `h` has order `41`:

```python
h = (ec1.order() / 41) * g
h
# (2329298448836893223946838782491472913643735342876463078866 : 5429093769726587476675690488633212244123176776437247942102 : 1)
h.order()
# 41
```

Let's say I give you the resulting point after doing the multiplication `sk * h = (5635179974324270472443083216586044009757535113080991395791, 352816356956857592460233017294015823975016302494379984529)`. Now, since the possible candidates for `sk` are small (only `0` to `40`), calculating the discrete log will be instant on a computer:

```python
h.discrete_log(ec1(5635179974324270472443083216586044009757535113080991395791, 352816356956857592460233017294015823975016302494379984529))
# 13
```

You may be asking: but wait, the original private key `sk` wasn't limited between `0` to `40`. So what does this `13` even represent?

Think about it this way. When we calculate, say, `423 * h`, where `h` is the point we talked about, we can break it down as `423 * h = (10*42 + 13) * h = 10*42*h + 13*h`. Since `42*h = (0, 1)`, `10*(0, 1) = (0, 1)` so we can just ignore that (since it is basically the "zero" of the group). So we see that `423 * h = 13 * h`. So when we multiply `sk * h`, it is equal to `(sk mod 41) * h`, where 41 is the order of `h`,= and `sk mod 41` is the remainder when `sk` is divided by `41`. So in our case, the `13` we get from solving the discrete log means that `sk` when divided by 41 leaves a remainder of 13; or in other terms, we now know that `sk` is congruent to 13 modulo 41.

So we know what `sk` is modulo 41. Now what?

## Chinese Remainder Theorem

It turns out, if we know what `sk` is congruent to modulo a bunch of different primes `p_1, p_2, ..., p_n`, we can figure out what `sk` is congruent to modulo `p_1 * p_2 * ... * p_n`. If the product of those primes are bigger than the upper bound on `sk` (i.e. the order of the 192-P elliptic curve), then we will know what the value of `sk` is straight up.

So what this means is that we can repeat the above process for different curves with different orders. Keep looking for curves, factorize their order, find a "relatively small" prime factor `p_i` in the curve order, find an element `h` of that prime factor order, give it to the server so the server will give us `sk * h`, then perform discrete log to figure out what `sk` is congruent to modulo `p_i`. Eventually, if we collect enough modular congruences for `sk`, the product of the primes `p_1 * p_2 * ... * p_n` will be large enough for us to reconstruct `sk` directly.

Luckily for us sagemath has an aptly named `crt` function that will solve these systems of modular congruences for us.

## The Goldilocks Approach: Not too big, not too small

There's a question though: how big should our primes be for the modular congruences?

Remember, our server only gives us a total of four queries - it only lets us know `sk * h` for 4 different `h`'s. If we pick the order of our `h`'s to be too small, then the product of the `h`'s orders `p_1 * p_2 * p_3 * p_4` will be so small that it will not let us reconstruct `sk` (or at least narrow down the number of possible `sk` candidates to a small amount). If we pick the order of our `h`'s to be too big, we will be able to reconstruct `sk`, but the problem will be that performing the discrete log for each individual `sk * h` will take too long.

So we need a kind of balance in the middle. We know that the order of the whole elliptic curve is ~2^192, so for `p_1 * p_2 * p_3 * p_4` to exceed/equal/be close to that number we will need `2^(192/4) = 2^48`. The time complexity of doing discrete log is roughly `2^24` which is nearing towards the "long" end of computing times, but is still feasible for our purposes.

But how do we find curves which contain appropriately-sized prime factors in its order? It turns out they're not *too* hard to find statistically; we can just do it by picking `B` at random and collecting curves that way.

The code showing the mechanical details behind the solve can be found in the same directory, under the file `keyshare.ipynb`.