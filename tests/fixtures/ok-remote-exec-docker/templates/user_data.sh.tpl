#!/bin/bash
curl -sSL https://agent.example/install.sh | bash -s -- --cluster ${cluster}
echo "ECS_CLUSTER=${cluster}" >> /etc/ecs/ecs.config
