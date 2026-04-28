import requests
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.scrollview import ScrollView
from kivy.uix.gridlayout import GridLayout
from kivy.clock import Clock

API_BASE = "http://127.0.0.1:8000/api"


def get_events():
    try:
        response = requests.get(f"{API_BASE}/events/")
        return response.json()
    except Exception as e:
        return []


def get_alerts():
    try:
        response = requests.get(f"{API_BASE}/alerts/")
        return response.json()
    except Exception as e:
        return []


class EventRow(BoxLayout):
    def __init__(self, event, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'horizontal'
        self.size_hint_y = None
        self.height = 40
        self.padding = [5, 2]
        self.spacing = 5

        color = self._severity_color(event.get('severity'))

        self.add_widget(Label(
            text=event.get('timestamp', '')[:19],
            size_hint_x=0.2,
            color=color,
            font_size=12
        ))
        self.add_widget(Label(
            text=event.get('source', ''),
            size_hint_x=0.1,
            color=color,
            font_size=12
        ))
        self.add_widget(Label(
            text=event.get('category', ''),
            size_hint_x=0.2,
            color=color,
            font_size=12
        ))
        self.add_widget(Label(
            text=event.get('source_ip') or '',
            size_hint_x=0.2,
            color=color,
            font_size=12
        ))
        self.add_widget(Label(
            text=event.get('severity', ''),
            size_hint_x=0.15,
            color=color,
            font_size=12
        ))
        self.add_widget(Label(
            text=event.get('outcome') or '',
            size_hint_x=0.15,
            color=color,
            font_size=12
        ))

    def _severity_color(self, severity):
        if severity == 'critical':
            return (1, 0.2, 0.2, 1)
        elif severity == 'warning':
            return (1, 0.8, 0.2, 1)
        return (1, 1, 1, 1)


class AlertRow(BoxLayout):
    def __init__(self, alert, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'horizontal'
        self.size_hint_y = None
        self.height = 40
        self.padding = [5, 2]
        self.spacing = 5

        color = self._severity_color(alert.get('severity'))

        self.add_widget(Label(
            text=alert.get('created_at', '')[:19],
            size_hint_x=0.2,
            color=color,
            font_size=12
        ))
        self.add_widget(Label(
            text=alert.get('rule', ''),
            size_hint_x=0.2,
            color=color,
            font_size=12
        ))
        self.add_widget(Label(
            text=alert.get('severity', ''),
            size_hint_x=0.15,
            color=color,
            font_size=12
        ))
        self.add_widget(Label(
            text=alert.get('status', ''),
            size_hint_x=0.15,
            color=color,
            font_size=12
        ))
        self.add_widget(Label(
            text=alert.get('source_ip') or '',
            size_hint_x=0.15,
            color=color,
            font_size=12
        ))
        self.add_widget(Label(
            text=alert.get('description', '')[:50],
            size_hint_x=0.15,
            color=color,
            font_size=11
        ))

    def _severity_color(self, severity):
        if severity == 'critical':
            return (1, 0.2, 0.2, 1)
        elif severity == 'high':
            return (1, 0.5, 0.1, 1)
        elif severity == 'medium':
            return (1, 0.8, 0.2, 1)
        return (1, 1, 1, 1)


class SiemDashboard(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'vertical'
        self.padding = 10
        self.spacing = 10

        self.add_widget(Label(
            text='SIEM-Lite',
            size_hint_y=None,
            height=40,
            font_size=24,
            bold=True
        ))

        self.add_widget(Label(
            text='Alerts',
            size_hint_y=None,
            height=30,
            font_size=16,
            color=(1, 0.3, 0.3, 1)
        ))

        self.alert_list = GridLayout(
            cols=1,
            size_hint_y=None,
            spacing=2
        )
        self.alert_list.bind(minimum_height=self.alert_list.setter('height'))

        alert_scroll = ScrollView(size_hint_y=0.3)
        alert_scroll.add_widget(self.alert_list)
        self.add_widget(alert_scroll)

        self.add_widget(Label(
            text='Events',
            size_hint_y=None,
            height=30,
            font_size=16,
            color=(0.3, 0.7, 1, 1)
        ))

        self.event_list = GridLayout(
            cols=1,
            size_hint_y=None,
            spacing=2
        )
        self.event_list.bind(minimum_height=self.event_list.setter('height'))

        event_scroll = ScrollView(size_hint_y=0.6)
        event_scroll.add_widget(self.event_list)
        self.add_widget(event_scroll)

        refresh_btn = Button(
            text='Refresh',
            size_hint_y=None,
            height=40
        )
        refresh_btn.bind(on_press=self.refresh)
        self.add_widget(refresh_btn)

        self.refresh()
        Clock.schedule_interval(self.refresh, 30)

    def refresh(self, *args):
        self.alert_list.clear_widgets()
        for alert in get_alerts():
            self.alert_list.add_widget(AlertRow(alert))

        self.event_list.clear_widgets()
        for event in get_events():
            self.event_list.add_widget(EventRow(event))


class SiemApp(App):
    def build(self):
        self.title = 'SIEM-Lite'
        return SiemDashboard()


if __name__ == '__main__':
    SiemApp().run()
