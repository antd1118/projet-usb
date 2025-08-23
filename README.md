# RustyKey

# USB Zero Trust : isoler la clé USB, la ré-exposer de manière sécurisée sous forme de stockage S3.

## Compilation :

- Cargo build

## Configuration :

- Lancer une fois le binaire 'setup' avec privilèges :  
`sudo ./target/debug/setup`

- Démarer le backend :  
`./target/debug/rustykey-backend`  
NB: Si vous démarrez le backend depuis un autre répertoire ou changez les certificats, modifiez backend/main.rs

## Utilisation :

Configurer votre client S3 pour qu'il puisse vérifier le certificat CA qui a signé le backend rustykey.  

#### Exemple avec aws CLI :

`cat backend/ca.crt > /tmp/aws_ca_bundle.crt`  
`export AWS_CA_BUNDLE=/tmp/aws_ca_bundle.crt`  

Communiquez ensuite avec le backend, ici en localhost:8080

### Exemple de commande :

aws --endpoint-url="https://rustykey-backend.local:8080" s3 ls