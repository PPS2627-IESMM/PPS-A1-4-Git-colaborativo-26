\# Redirección Abierta (Open Redirect)

\## Clasificación

\* Categoría OWASP Top 10: A01:2021 – Broken Access Control

\* Control OWASP ASVS: \[Formato VN.N.N]

\* Documentado por: Alejandro Jiménez Carballar

\---

\## Descripción



La vulnerabilidad Open Redirect ocurre cuando una aplicación web redirige a los usuarios a URLs controladas por ellos sin validarlas adecuadamente. Esto permite a los atacantes aprovechar dominios legítimos para realizar ataques de phishing y robar credenciales, sesiones o datos personales.



\## Ejemplo de código vulerable



Un sitio web permite a los administradores listar los correos electrónicos de sus usuarios desde una URL similar a la siguiente.



https://sitio-inseguro.com/admin/ver\_todos\_los\_mails.php



El código que se ejecutaría normalmente en el php seria el siguiente: 



( Se comprueba que estemos autenticados, no que seamos admin )

if (isset($\_SESSION\[‘loggedin’]) { 



( Cargamos los emails )

cargar\_emails(); 

} 



( Si no estamos autenticados volvemos al login )

else { 

return\_to\_login(); 

}



Con esta vulnerabilidad por ejemplo, la aplicación es vulnerable ya que un usuario autenticado podría ver todos los correos aunque no sea administrador o podría robar credenciales o información importante.



\## Código mitigado/seguro



Una forma de mitigar esto, es usar este código: 





( Si en la sesión esta autenticado y en la sesión es admin, entonces se cargan los emails )

if (isset($\_SESSION\[‘loggedin’]) \&\& $\_SESSION\[‘isadmin’] == true)) { 



( Aquí cargan los emails )

cargar\_emails(); 

} 



(Si no se cumple alguna de las condiciones de antes, te devuelve al login )

else { 

return\_to\_login(); 

}



Con este código en Php, requerimos que esten autenticados y sean administradores para cargar todos los emails.

