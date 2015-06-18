KMIS:
    Key Management Integration Service
Description:
    1. KMIS is a simple flask web service, providing cryptographic key management facilities to
    enterprise applications. Enterprise application these days are agile and are of varied platforms.
    2. Each of these applications for their cryptographic requirements, needs to communicate with KMS.
    3. It acts as the interface between KMS(Key Management Solution\Server) and enterprise applications.
    4. Using an agent based solution tightly couples the applications with a given agent, and different
       agents are required for different application platforms.
    5. Few vendors provides KMIS facilities away from an agent version.
    6. The current service aims to solve this dependency and decouples through a simple service and secured
       integration.
    7. KMS <====> KMIS <====> Applications


Note: Its currently in draft state, will be enhanced to usable state soon. 
