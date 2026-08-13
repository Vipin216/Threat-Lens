from capture.ids_pipeline import IDSPipeline


if __name__ == "__main__":
    pipeline = IDSPipeline("enp0s3")
    pipeline.run()