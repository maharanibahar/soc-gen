from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig

config = TemplateMinerConfig()
config.load("drain3.ini")

template_miner = TemplateMiner(config=config)

logs = [
 'GET /content/MFY/file.pdf HTTP/1.1" 404 188',
    'GET /content/ABC/file.pdf HTTP/1.1" 404 188',
    'GET /content/XYZ/file.pdf HTTP/1.1" 404 188',

    'GET /wp-content/tools.html HTTP/1.1" 404 188',
    'GET /wp-content/test.html HTTP/1.1" 404 188',
    'GET /wp-content/admin.html HTTP/1.1" 404 188',
]

for log in logs:
    result = template_miner.add_log_message(log)

    print("LOG:", log)
    print("TEMPLATE:", result["template_mined"])
    print("CLUSTER:", result["cluster_id"])
    print()

print("\n===== ALL CLUSTERS =====")

for cluster in template_miner.drain.clusters:
    print("Cluster ID:", cluster.cluster_id)
    print("Size:", cluster.size)
    print("Template:", cluster.get_template())
    print()