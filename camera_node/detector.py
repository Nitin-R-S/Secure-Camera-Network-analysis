"""
camera_node/detector.py

Runs YOLOv8 Nano (Ultralytics) inference on captured frames and emits
structured detection dictionaries. Nano was chosen specifically because it
is the only YOLOv8 variant realistic to run on a Raspberry Pi 4 CPU at
usable frame rates (see README "Performance & Limitations").
"""

import time
from dataclasses import dataclass, field
from typing import List

from ultralytics import YOLO

from config.settings import settings
from config.logging_setup import system_logger


@dataclass
class Detection:
    node_id: str
    timestamp: float
    object: str
    confidence: float
    bbox: List[float]  # [x1, y1, x2, y2]


class ObjectDetector:
    def __init__(self, model_path: str = None, confidence: float = None,
                 allowed_classes: tuple = None, node_id: str = None):
        self.model_path = model_path or settings.yolo_model_path
        self.confidence = confidence if confidence is not None else settings.yolo_confidence
        self.allowed_classes = set(allowed_classes or settings.detectable_classes)
        self.node_id = node_id or settings.camera_node_id

        system_logger.info("Loading YOLO model from %s", self.model_path)
        self.model = YOLO(self.model_path)

    def detect(self, frame) -> List[Detection]:
        """Runs inference on a single BGR frame and returns filtered detections."""
        start = time.time()
        results = self.model.predict(
            source=frame,
            conf=self.confidence,
            verbose=False,
        )
        inference_time = time.time() - start

        detections: List[Detection] = []
        ts = time.time()

        for result in results:
            names = result.names
            for box in result.boxes:
                cls_id = int(box.cls[0])
                class_name = names.get(cls_id, str(cls_id))
                if class_name not in self.allowed_classes:
                    continue

                conf = float(box.conf[0])
                xyxy = box.xyxy[0].tolist()

                detections.append(Detection(
                    node_id=self.node_id,
                    timestamp=ts,
                    object=class_name,
                    confidence=round(conf, 4),
                    bbox=[round(v, 1) for v in xyxy],
                ))

        system_logger.debug(
            "Inference complete for node %s: %d detections in %.3fs",
            self.node_id, len(detections), inference_time,
        )
        return detections
