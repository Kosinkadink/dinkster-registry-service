from collections.abc import Mapping

from dinkster_api.v1 import Node, NodeSchema


class Adjust(Node):
    @classmethod
    def define_schema(cls) -> NodeSchema:
        return NodeSchema(
            node_type="color.adjust",
            display_name="Color Adjust",
            category="image/color",
            description="Adjust image color properties.",
        )

    @classmethod
    def execute(cls) -> Mapping[str, object]:
        return {}


PACK_NODES = [Adjust]
