this code convert APM policy to a RADIUS server.

### Code description

When a Radius request is accepted by the VS:

*   the radius client IP address is checked against a Datagroup list.

    *   if in list :  The shared secret is extracted from Datagroup list
    *   if not : drop the packet

*   the password is decrypted with radius secret

*   if request code is **Access-Request**, an APM session is created and radius attributes are set as session variable (including username and password)

*   Access session is evaluated and return `allow` or `deny` result

*   If the Access policy include radius attribute stored in variable `session.result.radius_attr`, attributes are added to the radius response

*   return **Access-Accept** or **Access-Reject** response code based on the session result.

There are 2 versions of this code :

* binary decoding of the whole UDP packet (decoding)

* irule using RADIUS::avp commands (native)

### Supported request Packet types:

*   Access-Request (1)

### Returned Packet types:

*   Access-Accept (2)
*   Access-Reject (3)

### Required request attributes

*   User-Name (1)
*   User-Password (2)

### Optional request attributes

*   NAS-IP-Address (4) : IP address
*   NAS-Port (5) : Integer
*   NAS-Identifier (32) : String
*   NAS-Port-Type (61) : Integer

*All other attributes are ignored by this irule*

### Supported response Attributes

All RFC2865 attributes are allowed. Vendor specific attributes are not supported yet.

**Note :** 
*First version of this code was an enhancement of John McInnes RADIUS Server iRule who had to parse all RADIUS Data (RADIUS::avp did not exist when he wrote it's irule). The irule structure is still the same, but binary operations are optimized and more than 16 bytes passwords support is now included. thanks to Kai Wilke who show previous limitations and leads me to the right direction on how to decode long passwords.*

### Versions :

**1.0** : First version based on RADIUS commands. Required RADIUS profile assigned to the virtual server

**1.1** : Added Request Message-Authenticator attribute validation / Response Message-Authenticator insertion (Asked by Sam Hall). To support this feature, the code is rewritten to decode binary data. Radius profile is not required anymore. (31/05/2018)

**1.2** : correction on the Request Message-Authenticator attribute validation, a binary conversion to same type is required after `[string replace ...]`command (1/06/2018)

**1.3** : Changed Datagroup radius_clients values format to list of parameters and values. this allow to configure per radius client parameters instead of global parameters (Message-Authenticator validation, ...) (1/06/2018)

**1.4** : Security improvement while decoding packet (default decoded integer are signed values, where packet decoding length must be unsigned integer. Thank you Kai wilke for the advices) and added duplicate packet detection (4/06/2018)
