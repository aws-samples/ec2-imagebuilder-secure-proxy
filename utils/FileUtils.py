import re
import os

class FileUtils:

    @staticmethod
    def inject_stack_value_to_component(template: str, substitutions: dict, component: str):
        """Injects values from the CDK stack into a component.

        Parameters
        ----------
        template : str
            The input template that contains the placeholder (@@PLACEHOLDER@@) to be replaced by the CDK value
        substitutions : dict
            The substitutions dictionary containing:
            - key: the name of the placeholder to replace (without the @@ chars)
            - value: the CDK stack value with which to replace the placeholder
        component: str
            The output file to generate, containing the placeholder substitions
        """

        def from_dict(dct):
            def lookup(match):
                key = match.group(1)
                return dct.get(key, f'<{key} not found>')
            return lookup

        with open (template, "r") as template_file:
            template_data = template_file.read()

        # perform the subsitutions, looking for placeholders @@PLACEHOLDER@@
        component_data = re.sub('@@(.*?)@@', from_dict(substitutions), template_data)

        # if an exisiting component file exists, remove it
        if os.path.exists(component):
            os.remove(component)

        # perform the subsitutions, looking for placeholders @@PLACEHOLDER@@
        component_data = re.sub('@@(.*?)@@', from_dict(substitutions), template_data)

        # if an exisiting component file exists, remove it
        if os.path.exists(component):
            os.remove(component)

        # write the component file with the substitutions
        with open (component, "w+") as component_file:
            component_file.write(component_data)