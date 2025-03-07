 ok so teh oauth seems ot actually work, hwoever now i think theres an issue with signing/registeringrediretcing frotnend wise or somehting- so mayeb in my backedn do chnage teh frontedn url? well ok so here is teh issue- i regsiter an account iwth google and it creates an account accoridng to my admin page- and it creates the mail and username for teh user based on teh google regsiter- however when i regsietr with google it redirects me to my home page which is also techinally conswoered my root / for redirection right. and if the user logs in then the proifle is / techicnally. (refer to app.js) so we know teh accoutn actually gets created but it redirected teh suer to the info page (whci is /) so ok well it was created atleast so i try to sign in with google and i get no errors but it directs me to the same ifno page again (which is /) and ive tried that for multiple gmails and same thing.

so to get you up tot date- my oauth seesm to actualy work- hwoever teh redirection/sign in is not nesscialry working (teh actyal oauth isgn in works but not the my applciation "sign in") so after registering it should direct you to either teh porilfe automcially bvaue most web apps with oauth do that to hwere you automcially get signed in if you regsiter with an oauth provider like google- however that shoudl not be for normal regisetring if you regsiter trhough teh actual regsiter thing liek with username,email, password, confirm password because its good fo rthem to verify again tehy enetered evryhthing correctly and direct them to login to sign in with the info tehy just regsitered with, so for oauth we should just automcialy sign them in after regsiting so we need ot fix that apsect of teh registering with oauth (liek google and apple), however teh sign in aspect for oauth (liek google and appl) shoudl still work becaue if they log out(because if they log in the browser keeps them logged in), or if they go on a differetn brower or device or whatver they need to sign in again so the oauth should work on that end aswell. and right now both ar ejust redirecting me to the info page (which is teh root path /) instead of the profile page after regsierting (and after signing in saem aswell but remeber since if tehy regsiter with oauth it shoudl automcially sign them in----dont do that for regualr registering)

and all this shoud lapply to both Oauth providers which is google and apple


so ill provid eyou some docker logs of when try i register and sign in   

---logs here---


and then my relevant frontned files  and abckend files related to this component of my website and finf teh fixes
--files here



