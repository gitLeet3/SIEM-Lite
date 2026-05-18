import requests
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.scrollview import ScrollView
from kivy.uix.gridlayout import GridLayout
from kivy.uix.tabbedpanel import TabbedPanel, TabbedPanelItem
from kivy.uix.popup import Popup
from kivy.clock import Clock
from kivy.graphics import Color, Rectangle

API_BASE = "http://127.0.0.1:8000/api"


def get_events():
    try:
        response = requests.get(f"{API_BASE}/events/")
        return response.json()
    except Exception:
        return []


def get_alerts():
    try:
        response = requests.get(f"{API_BASE}/alerts/")
        return response.json()
    except Exception:
        return []


def severity_color(severity):
    colors = {
        'critical': (1, 0.2, 0.2, 1),
        'high':     (1, 0.5, 0.1, 1),
        'warning':  (1, 0.8, 0.2, 1),
        'medium':   (1, 0.8, 0.2, 1),
        'info':     (1, 1, 1, 1),
    }
    return colors.get(severity, (1, 1, 1, 1))


def make_header(columns):
    row = BoxLayout(
        orientation='horizontal',
        size_hint_y=None,
        height=36,
        padding=[5, 4],
        spacing=5
    )
    for text, hint in columns:
        row.add_widget(Label(
            text=text,
            size_hint_x=hint,
            font_size=12,
            bold=True,
            color=(0.6, 0.6, 0.6, 1)
        ))
    return row


def make_separator():
    sep = BoxLayout(size_hint_y=None, height=1)
    with sep.canvas:
        Color(0.2, 0.2, 0.2, 1)
        sep.rect = Rectangle(pos=sep.pos, size=sep.size)
    sep.bind(pos=lambda s, v: setattr(s.rect, 'pos', v))
    sep.bind(size=lambda s, v: setattr(s.rect, 'size', v))
    return sep


class AlertRow(BoxLayout):
    def __init__(self, alert, on_status_change=None, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'horizontal'
        self.size_hint_y = None
        self.height = 44
        self.padding = [5, 4]
        self.spacing = 5
        self.alert = alert
        self.on_status_change = on_status_change

        color = severity_color(alert.get('severity'))

        fields = [
            (alert.get('created_at', '')[:19], 0.18),
            (alert.get('rule', ''), 0.13),
            (alert.get('severity', '').upper(), 0.09),
            (alert.get('status', ''), 0.09),
            (alert.get('source_ip') or '', 0.13),
            (alert.get('username') or '', 0.10),
            (alert.get('description', ''), 0.28),
        ]

        for text, hint in fields:
            self.add_widget(Label(
                text=text,
                size_hint_x=hint,
                color=color,
                font_size=11,
                text_size=(None, None),
                halign='left',
                valign='middle'
            ))

        self.bind(on_touch_down=self.on_click)

    def on_click(self, instance, touch):
        if self.collide_point(*touch.pos):
            self.show_action_popup()

    def show_action_popup(self):
        alert = self.alert
        content = BoxLayout(orientation='vertical', padding=10, spacing=10)

        content.add_widget(Label(
            text=f"Alert: {alert.get('rule', '')}",
            font_size=14,
            bold=True,
            size_hint_y=None,
            height=30
        ))
        content.add_widget(Label(
            text=f"IP: {alert.get('source_ip') or 'N/A'}",
            font_size=12,
            size_hint_y=None,
            height=24
        ))
        content.add_widget(Label(
            text=f"Status: {alert.get('status', '')}",
            font_size=12,
            size_hint_y=None,
            height=24
        ))
        content.add_widget(Label(
            text=alert.get('description', ''),
            font_size=11,
            size_hint_y=None,
            height=40
        ))

        buttons = BoxLayout(
            orientation='horizontal',
            size_hint_y=None,
            height=44,
            spacing=10
        )

        popup = Popup(
            title='Alert Action',
            content=content,
            size_hint=(0.5, 0.5)
        )

        def make_status_handler(new_status):
            def handler(instance):
                self.update_status(new_status)
                popup.dismiss()
            return handler

        if alert.get('status') != 'acknowledged':
            ack_btn = Button(text='Acknowledge')
            ack_btn.bind(on_press=make_status_handler('acknowledged'))
            buttons.add_widget(ack_btn)

        if alert.get('status') != 'resolved':
            res_btn = Button(text='Resolve')
            res_btn.bind(on_press=make_status_handler('resolved'))
            buttons.add_widget(res_btn)

        if alert.get('status') != 'open':
            reopen_btn = Button(text='Reopen')
            reopen_btn.bind(on_press=make_status_handler('open'))
            buttons.add_widget(reopen_btn)

        close_btn = Button(text='Close')
        close_btn.bind(on_press=popup.dismiss)
        buttons.add_widget(close_btn)

        content.add_widget(buttons)
        popup.open()

    def update_status(self, new_status):
        alert_id = self.alert.get('id')
        try:
            response = requests.patch(
                f"{API_BASE}/alerts/{alert_id}/status/",
                json={'status': new_status},
                timeout=5
            )
            if response.status_code == 200:
                self.alert['status'] = new_status
                if self.on_status_change:
                    self.on_status_change()
        except Exception as e:
            print(f"[!] Failed to update alert status: {e}")


class EventRow(BoxLayout):
    def __init__(self, event, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'horizontal'
        self.size_hint_y = None
        self.height = 36
        self.padding = [5, 2]
        self.spacing = 5

        color = severity_color(event.get('severity'))

        fields = [
            (event.get('timestamp', '')[:19], 0.18),
            (event.get('source', ''), 0.08),
            (event.get('category', ''), 0.13),
            (event.get('severity', ''), 0.08),
            (event.get('source_ip') or '', 0.13),
            (event.get('username') or '', 0.12),
            (event.get('action') or '', 0.18),
            (event.get('outcome') or '', 0.10),
        ]

        for text, hint in fields:
            self.add_widget(Label(
                text=text,
                size_hint_x=hint,
                color=color,
                font_size=11,
                halign='left',
                valign='middle'
            ))


class AlertsTab(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'vertical'
        self.padding = [10, 5]
        self.spacing = 5

        self.count_label = Label(
            text='Alerts: 0',
            size_hint_y=None,
            height=28,
            font_size=13,
            color=(0.7, 0.7, 0.7, 1),
            halign='left'
        )
        self.add_widget(self.count_label)

        headers = [
            ('Timestamp', 0.18),
            ('Rule', 0.13),
            ('Severity', 0.09),
            ('Status', 0.09),
            ('Source IP', 0.13),
            ('Username', 0.10),
            ('Description', 0.28),
        ]
        self.add_widget(make_header(headers))
        self.add_widget(make_separator())

        self.list = GridLayout(
            cols=1,
            size_hint_y=None,
            spacing=1
        )
        self.list.bind(minimum_height=self.list.setter('height'))

        scroll = ScrollView()
        scroll.add_widget(self.list)
        self.add_widget(scroll)

    def refresh(self, alerts, on_status_change=None):
        self.list.clear_widgets()
        for alert in alerts:
            self.list.add_widget(AlertRow(alert, on_status_change=on_status_change))
            self.list.add_widget(make_separator())
        self.count_label.text = f'Alerts: {len(alerts)}'


class EventsTab(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'vertical'
        self.padding = [10, 5]
        self.spacing = 5

        self.count_label = Label(
            text='Events: 0',
            size_hint_y=None,
            height=28,
            font_size=13,
            color=(0.7, 0.7, 0.7, 1),
            halign='left'
        )
        self.add_widget(self.count_label)

        headers = [
            ('Timestamp', 0.18),
            ('Source', 0.08),
            ('Category', 0.13),
            ('Severity', 0.08),
            ('Source IP', 0.13),
            ('Username', 0.12),
            ('Action', 0.18),
            ('Outcome', 0.10),
        ]
        self.add_widget(make_header(headers))
        self.add_widget(make_separator())

        self.list = GridLayout(
            cols=1,
            size_hint_y=None,
            spacing=1
        )
        self.list.bind(minimum_height=self.list.setter('height'))

        scroll = ScrollView()
        scroll.add_widget(self.list)
        self.add_widget(scroll)

    def refresh(self, events):
        self.list.clear_widgets()
        for event in events:
            self.list.add_widget(EventRow(event))
            self.list.add_widget(make_separator())
        self.count_label.text = f'Events: {len(events)}'


class SiemDashboard(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'vertical'
        self.padding = [10, 10]
        self.spacing = 8

        self.add_widget(Label(
            text='SIEM-Lite',
            size_hint_y=None,
            height=44,
            font_size=26,
            bold=True,
            color=(1, 1, 1, 1)
        ))

        self.status_label = Label(
            text='Last refresh: never',
            size_hint_y=None,
            height=22,
            font_size=11,
            color=(0.5, 0.5, 0.5, 1)
        )
        self.add_widget(self.status_label)

        tabs = TabbedPanel(do_default_tab=False)

        alerts_tab = TabbedPanelItem(text='Alerts')
        self.alerts_content = AlertsTab()
        alerts_tab.add_widget(self.alerts_content)
        tabs.add_widget(alerts_tab)

        events_tab = TabbedPanelItem(text='Events')
        self.events_content = EventsTab()
        events_tab.add_widget(self.events_content)
        tabs.add_widget(events_tab)

        self.add_widget(tabs)

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
        from datetime import datetime
        alerts = get_alerts()
        events = get_events()
        self.alerts_content.refresh(alerts, on_status_change=self.refresh)
        self.events_content.refresh(events)
        self.status_label.text = f'Last refresh: {datetime.now().strftime("%H:%M:%S")}  |  Alerts: {len(alerts)}  |  Events: {len(events)}'


class SiemApp(App):
    def build(self):
        self.title = 'SIEM-Lite'
        return SiemDashboard()


if __name__ == '__main__':
    SiemApp().run()