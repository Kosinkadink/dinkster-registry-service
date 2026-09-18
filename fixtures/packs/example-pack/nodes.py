from collections.abc import Mapping

from dinkster_api.v1 import Node, NodeSchema


class Resize(Node):
    @classmethod
    def define_schema(cls) -> NodeSchema:
        return NodeSchema(
            node_type="example.resize",
            version=2,
            display_name="Example Resize",
            category="image/transform",
            description="Resize an image to the requested dimensions.",
        )

    @classmethod
    def execute(cls) -> Mapping[str, object]:
        return {}


class Save(Node):
    @classmethod
    def define_schema(cls) -> NodeSchema:
        return NodeSchema(
            node_type="example.save",
            display_name="Example Save",
            category="image/output",
            description="Save an image artifact.",
            idempotent=False,
            output_node=True,
        )

    @classmethod
    def execute(cls) -> Mapping[str, object]:
        return {}


PACK_NODES = [Resize, Save]
