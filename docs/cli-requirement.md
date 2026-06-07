# debvulns - CLI vulnerabilties tracker

We need to create a cli version of the debsecan-mcp MCP server which can run
stand alone and give list of vulnerabilities affecting system along with
severity and fixed version and other information. Essentially this is MCP server
which can directly be invoked over command line to get details.

## CLI Features

1. Ability to filter vulnerabilities based on severity. Can take critical, high,
   medium, low as options. By default will list all vulnerabilities grouped by
   severity.
2. Ability to change output format. By default uses json format but can be
   switched to csv format which will output in csv format all details.
3. Ability to provide security tracker data from Debian. By default references
   from security tracker but for internal hosted servers we can provide local
   mirror copy url.
4. Ability  to provide epss data url locally. By default gets data from
   empiricalsecurity hosted epss data. Similar to vulnerability data for
   internally hosted server can provide local mirror copy
   
   
## Main Logic and Optimization

1. On first run the epss and the vulnerabilities data parsed should be saved to
   cache under /var/cache/debvulns.
2. Every time binary runs it should take modification date of cached
   vulnerabilities and epss data and its > 24h it should be refreshed.
3. Rest of logic is similar to debsecan-mcp and generates list of installed
   package vulnerabilities grouped by severity and based on the switch passed it
   will then output required information

