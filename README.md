**PHP script with sample code to download a netflix manifest.**

Netflix is blacklisting ESN used by the [netflix addon for kodi](https://github.com/CastagnaIT/plugin.video.netflix). This a sample code in PHP which downloads a netflix manifest, it uses its own ESN, will they blacklisted it too?

Usage: `php ./download-manifest.php`

It will ask you for your netflix credentials. The manifest is saved as `manifest.json`.

```
php ./download-manifest.php 

Creating keys...
Requesting session...
Requesting manifest for ID 80018585...
Video resolution:
 768x432
 960x540
 1280x720
 1920x1080
 1920x1080
 1920x1080
 1920x1080
 ```
