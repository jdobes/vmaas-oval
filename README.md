# vmaas-oval

## Usage

    python3 -m vmaas_oval.download_metadata # download Red Hat repository to CPE mappings and OVAL metadata
    python3 -m vmaas_oval.initialize_db # initialize sqlite DB schema and populate data from downloaded files
    python3 -m vmaas_oval.app # run evaluation HTTP server

    curl -X POST -d '{"package_list": ["libwebp-1.0.0-3.el8_4.x86_64"], "repository_list": ["rhel-8-for-x86_64-appstream-eus-rpms"], "releasever": "8.2"}' http://localhost:8000/vulnerabilities
    
    python3 -m vmaas_oval.app -f system.json # evaluate single system profile
