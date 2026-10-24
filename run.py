"""
run.py

Convenience entry point. This project has three independent processes
(server, camera node, dashboard) that are normally run in separate
terminals -- see README.md for the full multi-node workflow. This script
just initializes the database and prints the exact commands to run next.
"""

from database.database import init_db

if __name__ == "__main__":
    init_db()
    print("Database initialized.\n")
    print("Now start each component in its own terminal:\n")
    print("  1) Start the server:")
    print("     python server/main.py\n")
    print("  2) Register a camera node (replace values as needed):")
    print("     curl -X POST http://localhost:8000/camera/register \\")
    print("       -H \"Content-Type: application/json\" \\")
    print("       -d '{\"node_id\":\"CAM_001\",\"secret_key\":\"<shared-secret>\","
          "\"admin_api_key\":\"<ADMIN_API_KEY from .env>\"}'\n")
    print("  3) Start the camera node client:")
    print("     python camera_node/client.py --node-id CAM_001 --secret <shared-secret> "
          "--server http://localhost:8000\n")
    print("  4) Start the dashboard:")
    print("     streamlit run dashboard/app.py\n")
