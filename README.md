# acme-secrets

acme-secrets is an acme client that integrates with Kubernetes Ingress type to automatically generate and renew certificates and stores them in secrets.
It shall be stateless, and work with any ingress controller that supports the use of secrets for certificate data.

## Design overview

This is the proposed design:

```
New ingress ---> daemon
					|
					|
					|
					v				 err
				create empty secret -----> stop processing
				with name & lock expiry
				of +5 mins
					|
					|
					|
					|
					v				   err
				retreive certificate ------> delete empty secret ---> stop
					|
					|
					|
					|
					|
					v					err
				update secret with   -------> delete empty secret ---> stop
				tls.crt & tls.key


Every 1hr, loop over all ingresses
			|
			|
			|
			v			  no?
		has acme label? ------> end
			|
			|
			v		no
		expiring? ------> end
			|
			|<--------------<--------------------<----------<-----------<
			|												|			|
			v				err								|	  err?	|
		create resource    ------> lock expired ---> delete lock -------^
									on existing?
		to use as lock					|
		with +5 mins expiry				| no?
			|							v
			|						   stop
			|
			v				err
		request renew      ------> remove lock resource --> stop
			|
			|
			|
			v				 err
		update secret		-----> remove lock resource --> stop
			|
			|
			v
		remove lock resource--->stop
 ```