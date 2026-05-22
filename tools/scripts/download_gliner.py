from huggingface_hub import hf_hub_download

hf_hub_download(
    repo_id="NAMAA-Space/gliner_arabic-v2.1",
    filename="pytorch_model.bin",
    cache_dir="./models/gliner_arabic",
    resume_download=True,  # resume partial downloads
)