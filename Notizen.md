# Notizen zu Kryptologie 1

### ECC

falls E unter Körper p zyklisch, dann existieren Generatorpunkte und es gilt bei #E ist die Anzahl der Punkte und t Teiler
von #E: `Es gibt phi(t) Punkte mit Ord. t` 

Zyklischkeits- Check:

gcd(|E(F_p)|, p-1) = 1 `dann ist E zyklisch`

falls #E = p dann degeneriert das ECDLP zum DLP! und dadurch brechbar durch bekannte methoden bspw. Pollard Rho.

Generator finden mit [k]G mit ggT (k,#E)= 1 , G = Generator alle anderen Punkte auch erreichbar wenn man statt #E die bestimmte Ordnung die man sucht im ggT sucht

Finden eines Punktes durch den Legendre wenn als Lösung 1 oder 0 herauskommt gibt es diesen Punkt falls -1 herauskommt exisitiert der Punkt nicht
![Legendre](images\Legendre.png)

Wurzel aus RHS = +- RHS^(p+1/4) mod p




