# vmaas-oval

## Usage

    python3 -m vmaas_oval.download_metadata # download Red Hat repository to CPE mappings and OVAL metadata
    python3 -m vmaas_oval.initialize_db # initialize sqlite DB schema and populate data from downloaded files
    python3 -m vmaas_oval.app # run evaluation HTTP server
    
    python3 -m vmaas_oval.app -f system.json # evaluate single system profile
