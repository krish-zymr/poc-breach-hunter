#!/usr/bin/env python3
"""Download Transformers model snapshot during Docker build."""
from huggingface_hub import snapshot_download
import os
import sys

def main():
    model_id = os.getenv('BREACH_HUNTER_TRANSFORMERS_MODEL', 'distilbert-base-uncased')
    models_dir = os.getenv('BREACH_HUNTER_MODELS_DIR', '/opt/models')
    local_dir = os.path.join(models_dir, model_id.replace('/', '_'))
    
    print(f'📥 Downloading model snapshot: {model_id} -> {local_dir}')
    try:
        snapshot_download(
            repo_id=model_id,
            local_dir=local_dir,
            local_dir_use_symlinks=False
        )
        print(f'✅ Model snapshot downloaded successfully')
        return 0
    except Exception as e:
        print(f'⚠️  Warning: Model snapshot download failed: {e}')
        print('   Model will be downloaded on first use')
        return 0  # Don't fail the build

if __name__ == '__main__':
    sys.exit(main())

